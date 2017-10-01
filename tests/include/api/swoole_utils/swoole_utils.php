<?php

//swoole_function swoole_get_local_ip() {}
//swoole_function swoole_strerror($errno) {}
//swoole_function swoole_errno() {}

require_once __DIR__ . "/../../../include/bootstrap.php";


$ip_list = swoole_get_local_ip();
print_r($ip_list);


echo swoole_errno(), "\n";
echo swoole_strerror(swoole_errno());