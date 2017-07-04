<?php

require_once __DIR__ . "/swoole_mysql_init.php";

swoole_mysql_query("select 1", function($mysql_result, $result) {
    swoole_event_exit();
    fprintf(STDERR, "SUCCESS\n");
});