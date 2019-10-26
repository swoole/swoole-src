--TEST--
swoole_runtime: get hook flags
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();
var_dump(Swoole\Runtime::getHookFlags());

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL | SWOOLE_HOOK_CURL);
var_dump(Swoole\Runtime::getHookFlags());
?>
--EXPECT--
int(1879048191)
int(2147483647)
