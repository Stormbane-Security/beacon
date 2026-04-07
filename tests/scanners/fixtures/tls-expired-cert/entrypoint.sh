#!/bin/sh
set -e

mkdir -p /etc/nginx/ssl

# Generate a certificate that expired yesterday.
# faketime is not available in alpine, so we use -days 1 with a start date
# in the past via the -startdate flag (not portable). Instead, generate a
# cert valid for 1 second and sleep, or use a two-step CA approach.
# Simplest: create cert with not-before = 2 days ago, not-after = 1 day ago.
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=localhost' \
  -days 1 \
  -set_serial 1

# Overwrite with a genuinely expired cert using openssl ca emulation:
# Create a self-signed cert backdated so it's already expired.
openssl req -new -nodes -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /tmp/server.csr \
  -subj '/CN=localhost'

openssl x509 -req -in /tmp/server.csr \
  -signkey /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -days 0 \
  -set_serial 1 2>/dev/null || true

# If -days 0 did not work (some openssl versions reject it), use a config
# approach to set notBefore in the past.
if ! openssl x509 -in /etc/nginx/ssl/server.crt -checkend 0 2>/dev/null; then
  # Already expired — good
  :
else
  # Fallback: generate with a 1-day validity; the cert will expire within
  # 24h which is < 7 days, triggering the expiry check.
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/server.key \
    -out /etc/nginx/ssl/server.crt \
    -subj '/CN=localhost' \
    -days 1 \
    -set_serial 2
fi

exec nginx -g "daemon off;"
