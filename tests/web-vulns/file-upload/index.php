<?php
// Deliberately vulnerable file upload form
?>
<html>
<body>
<h1>File Upload</h1>
<form action="upload.php" method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
</body>
</html>
