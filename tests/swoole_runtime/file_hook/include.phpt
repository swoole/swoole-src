--TEST--
swoole_runtime/file_hook: include
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

swoole\runtime::enableCoroutine();

go(function () {
    include __DIR__."/a.inc";
    include __DIR__."/b.inc";
    include __DIR__ . "/../../include/lib/class.websocket_client.php";
});
swoole_event_wait();
?>
--EXPECT--
A
B
