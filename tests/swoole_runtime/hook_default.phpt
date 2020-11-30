--TEST--
swoole_runtime: enable hook by default
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    Assert::eq(Swoole\Runtime::getHookFlags(), SWOOLE_HOOK_ALL);
});

?>
--EXPECT--
