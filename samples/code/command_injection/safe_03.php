<?php
$target = $_GET['target'];
system("ls " . escapeshellarg($target));
?>
