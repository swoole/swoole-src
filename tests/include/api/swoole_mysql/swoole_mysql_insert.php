<?php

require_once __DIR__ . "/swoole_mysql_init.php";


$sql = "insert into ad (`kdt_id`, `num`, `data`, `valid`, `created_time`, `update_time`) 
VALUES (99999, 1, 'data', 1, 0, 0)";

swoole_mysql_query($sql, function($swoole_mysql, $result) {

    ob_start();
    assert($result === true);
    assert($swoole_mysql->errno === 0);
    if ($buf = ob_get_clean()) {
        fprintf(STDERR, $buf);
    }

    swoole_event_exit();
    fprintf(STDERR, "SUCCESS");
});