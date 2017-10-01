<?php

require_once __DIR__ . "/swoole_mysql_init.php";

swoole_mysql_query("select", function($mysql_result, $result) {
    if ($mysql_result->errno === 1064) {
        fprintf(STDERR, "SUCCESS");
    } else {
        fprintf(STDERR, "FAIL");
    }
    swoole_event_exit();
});