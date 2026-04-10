#!/bin/sh
set -e

mkdir -p /etc/nginx/ssl /tmp/ca/newcerts
touch /tmp/ca/index.txt
echo '01' > /tmp/ca/serial

# Create a throwaway CA
openssl genrsa -out /tmp/ca/ca.key 2048 2>/dev/null
openssl req -new -x509 -key /tmp/ca/ca.key -out /tmp/ca/ca.crt \
  -days 1 -subj '/CN=TestCA' 2>/dev/null

# Generate server key + CSR
openssl genrsa -out /etc/nginx/ssl/server.key 2048 2>/dev/null
openssl req -new -key /etc/nginx/ssl/server.key -out /tmp/server.csr \
  -subj '/CN=localhost' 2>/dev/null

# Sign with dates in the past → certificate already expired
cat > /tmp/ca.cnf <<'ENDCNF'
[ca]
default_ca = CA_default
[CA_default]
dir              = /tmp/ca
database         = /tmp/ca/index.txt
serial           = /tmp/ca/serial
new_certs_dir    = /tmp/ca/newcerts
certificate      = /tmp/ca/ca.crt
private_key      = /tmp/ca/ca.key
default_md       = sha256
policy           = policy_any
[policy_any]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
ENDCNF

openssl ca -config /tmp/ca.cnf -batch \
  -startdate 20250101000000Z \
  -enddate   20250102000000Z \
  -in /tmp/server.csr \
  -out /etc/nginx/ssl/server.crt 2>/dev/null

exec nginx -g "daemon off;"
