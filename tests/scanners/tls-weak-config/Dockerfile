FROM nginx:1.25-alpine
RUN apk add --no-cache openssl
# Enable legacy TLS 1.0/1.1 in OpenSSL 3.x — required for weak protocol test
RUN sed -i 's/^\[openssl_init\]/[openssl_init]\nssl_conf = ssl_sect/' /etc/ssl/openssl.cnf && \
    printf '\n[ssl_sect]\nsystem_default = system_default_sect\n\n[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT:@SECLEVEL=0\n' >> /etc/ssl/openssl.cnf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
