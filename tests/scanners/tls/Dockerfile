FROM nginx:1.25-alpine
RUN apk add --no-cache openssl
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# Remove default HTTP server block to avoid port 80 conflict
RUN rm -f /etc/nginx/conf.d/default.conf.bak
ENTRYPOINT ["/entrypoint.sh"]
