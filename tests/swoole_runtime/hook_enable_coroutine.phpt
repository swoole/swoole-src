--TEST--
swoole_runtime: enableCoroutine
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_TCP);

Co\run(function () {
    Assert::eq(Swoole\Runtime::getHookFlags(), SWOOLE_HOOK_TCP);
});

Co\run(function () {
    Assert::eq(Swoole\Runtime::getHookFlags(), SWOOLE_HOOK_TCP);
});

?>
--EXPECT--
