--TEST--
swoole_redis: connect timeout

--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_redis/connect_timeout.php';

?>
--EXPECT--
