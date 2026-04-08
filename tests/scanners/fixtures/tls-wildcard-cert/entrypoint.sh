#!/bin/sh
set -e

mkdir -p /etc/nginx/ssl

# Generate a wildcard certificate for *.example.com
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=*.example.com'

exec nginx -g "daemon off;"
