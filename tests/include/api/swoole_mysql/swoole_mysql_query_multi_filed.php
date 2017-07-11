<?php

require_once __DIR__ . "/swoole_mysql_init.php";


$n = 1024 * 1024;
$fields = implode(", ", range(0, $n - 1));

swoole_mysql_query("select $fields", function($swoole_mysql, $result) {
    if ($swoole_mysql->errno === 0) {
        fprintf(STDERR, "SUCCESS");
    } else {
        fprintf(STDERR, "ERROR");
    }
    swoole_event_exit();
});