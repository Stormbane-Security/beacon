#!/bin/sh
set -e

mkdir -p /etc/nginx/ssl

# Generate SHA-1 signed cert (weak signature), 730-day validity (exceeds 398-day
# CA/B Forum limit), CN-only with no SAN (deprecated practice).
openssl req -x509 -sha1 -nodes -days 730 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=localhost'

exec nginx -g "daemon off;"
