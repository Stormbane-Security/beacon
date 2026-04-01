#!/bin/sh
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=localhost'
