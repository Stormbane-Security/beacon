#!/bin/sh
set -e

mkdir -p /etc/nginx/ssl

# Generate a 1024-bit RSA key — deliberately weak for testing
openssl req -x509 -nodes -days 365 -newkey rsa:1024 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=localhost'

exec nginx -g "daemon off;"
