#!/bin/sh
set -e

mkdir -p /etc/nginx/ssl

# Self-signed cert with SAN, no OCSP, no SCT, no CRL distribution point
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'

exec nginx -g "daemon off;"
