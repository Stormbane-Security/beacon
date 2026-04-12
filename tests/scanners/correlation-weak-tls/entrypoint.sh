#!/bin/sh
set -e
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=login.internal.corp/O=Weak TLS Test' \
  -days 365
exec nginx -g "daemon off;"
