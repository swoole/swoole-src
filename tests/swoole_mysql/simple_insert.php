<?php
require_once __DIR__ . "/../include/swoole.inc";

fork_exec(function() {
    require_once __DIR__ . "/../include/api/swoole_mysql/swoole_mysql_insert.php";
});
?>
