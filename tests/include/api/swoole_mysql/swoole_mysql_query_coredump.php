<?php

require_once __DIR__ . "/swoole_mysql_init.php";


swoole_mysql_query("select 1", function($swoole_mysql, $result) {
    swoole_event_exit();
    fprintf(STDERR, "SUCCESS");
});