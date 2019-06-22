--TEST--
swoole_mysql_coro: reset test mysql database
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$init_script = __DIR__ . '/../init';
`php {$init_script} > /dev/null`;
?>
--EXPECT--
