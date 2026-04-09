<?php
if (isset($_GET['debug'])) {
    echo "DEBUG MODE: " . $_GET['debug'];
} else {
    echo "Normal page";
}
