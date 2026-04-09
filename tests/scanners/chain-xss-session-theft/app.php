<?php
setcookie("session", "abc123", ["path" => "/"]); // No HttpOnly!
$q = $_GET['q'] ?? '';
echo "<html><body>Search: $q</body></html>";
