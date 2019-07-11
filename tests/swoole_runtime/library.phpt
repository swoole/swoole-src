--TEST--
swoole_runtime: library
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
var_dump(SWOOLE_LIBRARY);
?>
--EXPECT--
bool(true)
