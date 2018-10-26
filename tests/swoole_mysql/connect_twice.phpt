--TEST--
swoole_mysql: connect_twice
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('foreign network dns error');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

fork_exec(function() {
    require __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_connect_twice.php';
});
?>
--EXPECT--
SUCCESS
closed
