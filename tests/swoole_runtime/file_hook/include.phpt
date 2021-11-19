--TEST--
swoole_runtime/file_hook: include
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

go(function () {
    include __DIR__."/a.inc";
    include __DIR__."/b.inc";
});
Swoole\Event::wait();
?>
--EXPECT--
A
B
