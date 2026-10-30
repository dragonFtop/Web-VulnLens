<?php
$ip = $_GET['ip'];
system("ping -c 1 " . $ip);
?>
