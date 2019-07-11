--TEST--
swoole_client_async: connect twice
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_client/connect_twice.php';
?>
--EXPECT--
error
