--TEST--
swoole_client_coro: close socket property
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    Assert::true($cli->connect('www.baidu.com', 80));
    Assert::true($cli->connected);
    $socket = $cli->exportSocket();
    $socket->close();
    Assert::false($cli->recv());
    Assert::false($cli->close());
});
Swoole\Event::wait();
?>
--EXPECT--
