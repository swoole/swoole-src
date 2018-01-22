<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__."/../include/api/swoole_mysql/swoole_mysql_init.php";
fork_exec(function() {
    require_once __DIR__ . "/../include/api/swoole_mysql/swoole_mysql_refcout.php";
});
?>
