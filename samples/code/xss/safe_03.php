<?php
$name = $_GET['name'];
echo "<h1>Welcome, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</h1>";
?>
