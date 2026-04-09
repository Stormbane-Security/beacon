<?php
$id = $_GET['id'] ?? '1';
// VULNERABLE: directly interpolated into query simulation
// Simulate a DB query that's vulnerable to time-based injection
if (preg_match('/sleep/i', $id)) {
    $delay = 0;
    if (preg_match('/sleep\((\d+)\)/i', $id, $m)) $delay = min((int)$m[1], 5);
    sleep($delay);
}
echo json_encode(["id" => $id, "name" => "Product"]);
