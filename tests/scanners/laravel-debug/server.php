<?php
/**
 * Minimal PHP server that mimics Laravel fingerprints:
 * - laravel_session cookie
 * - X-Powered-By header referencing Laravel
 * - XSRF-TOKEN cookie
 */
header("X-Powered-By: PHP/8.2 Laravel");
header("Set-Cookie: laravel_session=eyJpdiI6InRlc3QiLCJ2YWx1ZSI6InRlc3QifQ==; path=/; httponly");
header("Set-Cookie: XSRF-TOKEN=test-xsrf-token; path=/");
header("Content-Type: text/html; charset=UTF-8");

echo '<html><head><title>Laravel App</title></head>';
echo '<body>';
echo '<h1>Welcome to Laravel</h1>';
echo '<meta name="csrf-token" content="test-csrf-token">';
echo '</body></html>';
