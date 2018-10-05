--TEST--
swoole_http_client: connect_port_not_listen

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_http_client/connect_port_not_listen.php';
?>
--EXPECT--
error