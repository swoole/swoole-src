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
Fatal error: Uncaught Swoole\Exception: eventLoop has already been created. unable to create Swoole\Server in %s:%d
Stack trace:
#0 %s(%d): Swoole\Server->__construct('127.0.0.1')
#1 {main}
  thrown in %s on line %d
