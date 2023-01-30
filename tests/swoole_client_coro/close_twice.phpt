--TEST--
swoole_client_coro: close twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $cli->connect('www.baidu.com', 80);
    Assert::true($cli->close());
    Assert::false($cli->close());
    Assert::eq($cli->errCode, SOCKET_EBADF);
});
Swoole\Event::wait();
?>
--EXPECT--
