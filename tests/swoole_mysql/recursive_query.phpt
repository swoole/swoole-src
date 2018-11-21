--TEST--
swoole_mysql: recursive query
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
fork_exec(function() {
    require __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_recursive_query.php';
});
?>
--EXPECT--
SUCCESS
closed
