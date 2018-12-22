--TEST--
swoole_mysql: test refcount
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_init.php';
fork_exec(function() {
    require __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_refcout.php';
});
?>
--EXPECT--
SUCCESS
