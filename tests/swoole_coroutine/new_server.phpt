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
Fatal error: Uncaught Swoole\Error: must be forked outside the coroutine in %s:%d
Stack trace:
#0 %s(6): Swoole\Server->start()
#1 {main}
  thrown in %s on line %d
[%s]	ERROR	zm_deactivate_swoole (ERRNO 503): Fatal error: Uncaught Swoole\Error: must be forked outside the coroutine in %s:%d
Stack trace:
#0 %s(6): Swoole\Server->start()
#1 {main}
  thrown in %s on line %d
