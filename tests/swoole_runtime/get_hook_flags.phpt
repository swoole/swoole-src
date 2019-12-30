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
Assert::same(Swoole\Runtime::getHookFlags(), SWOOLE_HOOK_ALL);

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL | SWOOLE_HOOK_CURL);
Assert::same(Swoole\Runtime::getHookFlags(), SWOOLE_HOOK_ALL | SWOOLE_HOOK_CURL);
?>
--EXPECT--
