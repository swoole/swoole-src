<?php
$db = new mysqli;
$db->connect('127.0.0.1', 'root', 'root', 'test');
echo swoole_mysqli_get_sock($db);
