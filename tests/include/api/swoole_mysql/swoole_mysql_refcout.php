<?php

require_once __DIR__ . "/../../../include/bootstrap.php";


$i = 10000;
$start = $end = 0;
while($i--) {
    if ($i == 99) {
        $start = memory_get_usage();
    }
    // 不应该在构造函数加引用计数
    $swoole_mysql = new \swoole_mysql();
    // xdebug_debug_zval("swoole_mysql"); // 2
    if ($i == 1) {
        $end = memory_get_usage();
    }
}


if (($end - $start) < 1000) {
    fprintf(STDERR, "SUCCESS");
} else {
    fprintf(STDERR, "FAIL");
}
swoole_event_exit();
