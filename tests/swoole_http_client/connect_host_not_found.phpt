--TEST--
swoole_http_client: connect_host_not_found

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_http_client/connect_host_not_found.php';
// 实际期望输出error
?>
--EXPECT--
error