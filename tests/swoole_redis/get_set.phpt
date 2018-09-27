--TEST--
swoole_redis: get & set
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/api/swoole_redis/simple_redis.php';
?>
--EXPECT--
close