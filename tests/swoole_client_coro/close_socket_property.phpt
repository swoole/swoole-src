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
    Assert::true($cli->socket->close());
    Assert::false($cli->close());
    Assert::eq($cli->errCode, SOCKET_EBADF);
    Assert::false($cli->connected);
    Assert::null($cli->socket);
    Assert::true($cli->connect('www.baidu.com', 80));
});
Swoole\Event::wait();
?>
--EXPECT--
