#!/bin/sh
set -e

# Generate self-signed certificate if not present
if [ ! -f /etc/nginx/certs/server.crt ]; then
    mkdir -p /etc/nginx/certs
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/certs/server.key \
        -out /etc/nginx/certs/server.crt \
        -subj "/CN=localhost/O=BeaconTest/C=US"
fi

exec nginx -g "daemon off;"
