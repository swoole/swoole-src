<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__."/../include/api/swoole_mysql/swoole_mysql_init.php";

swoole_mysql_query("select", function($mysql, $result) {
    if ($mysql->errno === 1064) {
        fprintf(STDERR, "SUCCESS\n");
    } else {
        fprintf(STDERR, "FAIL\n");
    }
    $mysql->close();
});
?>
