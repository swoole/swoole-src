--TEST--
swoole_http2_client_coro: cookies
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $cli = new Swoole\Coroutine\Http2\Client('192.0.0.1', 9000);
    $cli->set(['timeout' => 0.1]);
    Assert::false($cli->connect());
    Assert::eq($cli->errCode, SOCKET_ETIMEDOUT);
    Assert::false($cli->send(new Swoole\Http2\Request));
    Assert::eq($cli->errCode, SOCKET_ECONNRESET);
    Assert::false($cli->recv(1));
    Assert::eq($cli->errCode, SOCKET_ECONNRESET);
});
Swoole\Event::wait();
?>
--EXPECT--
