FROM php:8.2-apache

# Enable mod_rewrite
RUN a2enmod rewrite

# Create real PHP files at discoverable paths
RUN mkdir -p /var/www/html/admin

# Real PHP admin panel
RUN echo '<?php echo "PHP Admin Panel - " . phpversion(); ?>' > /var/www/html/admin.php

# Real PHP files in admin directory
RUN echo '<?php echo json_encode(["db_host" => "localhost", "db_name" => "app"]); ?>' > /var/www/html/admin/config.php
RUN echo '<?php echo "Backup manager v1.0"; ?>' > /var/www/html/admin/backup.php

# Health check
RUN echo '<?php echo "OK"; ?>' > /var/www/html/health.php

# Index
RUN echo '<?php echo "<h1>Welcome</h1>"; ?>' > /var/www/html/index.php

EXPOSE 80
