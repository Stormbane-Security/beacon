FROM php:8.2-apache
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads
COPY index.php /var/www/html/index.php
COPY upload.php /var/www/html/upload.php
EXPOSE 80
