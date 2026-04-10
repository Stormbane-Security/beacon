<!DOCTYPE html>
<html>
<head><title>Product Search</title></head>
<body>
<h1>Product Search</h1>
<form method="GET" action="/search.php">
  <input type="text" name="q" value="<?php echo isset($_GET['q']) ? $_GET['q'] : ''; ?>">
  <button type="submit">Search</button>
</form>
<?php if (isset($_GET['q']) && $_GET['q'] !== ''): ?>
  <h2>Results for: <?php echo $_GET['q']; ?></h2>
  <p>No products found matching "<?php echo $_GET['q']; ?>".</p>
<?php endif; ?>
</body>
</html>
