--TEST--
swoole_function: test swoole_clear_dns_cache
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_clear_dns_cache();
?>
--EXPECT--
