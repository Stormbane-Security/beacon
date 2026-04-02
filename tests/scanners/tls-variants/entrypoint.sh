#!/bin/sh
# Enable legacy TLS 1.0/1.1 in OpenSSL 3.x — required for the test.
if grep -q '^\[openssl_init\]' /etc/ssl/openssl.cnf 2>/dev/null; then
  sed -i 's/^\[openssl_init\]/[openssl_init]\nssl_conf = ssl_sect/' /etc/ssl/openssl.cnf
  printf '\n[ssl_sect]\nsystem_default = system_default_sect\n\n[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT:@SECLEVEL=0\n' >> /etc/ssl/openssl.cnf
fi

mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/server.key \
  -out /etc/nginx/ssl/server.crt \
  -subj '/CN=localhost'
