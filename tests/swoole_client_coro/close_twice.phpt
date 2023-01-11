--TEST--
swoole_client_coro: close twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $cli->close();
    $cli->close();
});
Swoole\Event::wait();
?>
--EXPECT--
