--TEST--
swoole_mysql: recursive query
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_docker('onClose event lost');
?>
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