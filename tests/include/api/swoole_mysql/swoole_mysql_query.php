<?php

require_once __DIR__ . "/swoole_mysql_init.php";


swoole_mysql_query("select kdt_id, num, `data` from ad", function($swoole_mysql, $result) {
    assert($swoole_mysql->errno === 0);
    // var_dump($swoole_mysql);
    
    if (is_array($result)) {
        // var_export($result);
    } else {
        fprintf(STDERR, $result);
        fprintf(STDERR, "error");
    }
    swoole_event_exit();
    fprintf(STDERR, "SUCCESS");
});