--TEST--
swoole_coroutine: new server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $server = new Swoole\Server('127.0.0.1');
    $server->on('receive', function () { });
    $server->start();
});
?>
--EXPECTF--
[%s]	ERROR	(PHP Fatal Error: %d):
Swoole\Server::start: must be forked outside the coroutine
Stack trace:
#0  Swoole\Server->start() called at [%s/tests/swoole_coroutine/new_server.php:%d]
