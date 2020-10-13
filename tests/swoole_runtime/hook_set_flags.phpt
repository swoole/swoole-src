--TEST--
swoole_runtime: set hook flags
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co::set(['hook_flags' => 0]);

Co\run(function () {
    Assert::eq(Swoole\Runtime::getHookFlags(), 0);
});

Co::set(['hook_flags' => SWOOLE_HOOK_CURL]);

Co\run(function () {
    Assert::eq(Swoole\Runtime::getHookFlags(), SWOOLE_HOOK_CURL);
});

?>
--EXPECT--
