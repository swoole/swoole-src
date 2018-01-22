<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__."/../include/api/swoole_mysql/swoole_mysql_init.php";

swoole_mysql_query("select 1", function($swoole_mysql, $result) {
    fprintf(STDERR, "SUCCESS\n");
    $swoole_mysql->close();
});
?>
