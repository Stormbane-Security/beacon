<?php
// VULNERABLE: only checks Content-Type header, not actual file content or extension
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $target = 'uploads/' . basename($_FILES['file']['name']);

    // VULNERABLE: trusts client-provided Content-Type
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
    if (in_array($_FILES['file']['type'], $allowed_types)) {
        // VULNERABLE: no extension check, no content verification
        if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            echo "File uploaded to: " . $target;
        } else {
            echo "Upload failed";
        }
    } else {
        echo "Only images allowed (type: " . $_FILES['file']['type'] . ")";
    }
} else {
    echo "No file uploaded";
}
?>
