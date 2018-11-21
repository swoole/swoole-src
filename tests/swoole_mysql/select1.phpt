--TEST--
swoole_mysql: select 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_init.php';

fork_exec(function() {
    swoole_mysql_query("select 1", function($mysql_result, $result) {
        swoole_event_exit();
        fprintf(STDERR, "SUCCESS\n");
    });
});
?>
--EXPECT--
SUCCESS
closed
