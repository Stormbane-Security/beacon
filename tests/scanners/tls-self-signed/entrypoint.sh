#!/bin/sh
set -e

mkdir -p /etc/nginx/ssl

# Generate a self-signed certificate (2048-bit RSA — minimum for modern nginx).
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=localhost/O=Test Self-Signed' \
  -days 365

exec nginx -g "daemon off;"
