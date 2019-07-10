--TEST--
swoole_socket_coro: accept
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($sock->bind('127.0.0.1', 9601));
    Assert::assert($sock->listen(512));
    $conn = $sock->accept();
    Assert::assert($conn);
    Assert::isInstanceOf($conn, Swoole\Coroutine\Socket::class);

    $data = $conn->recv();
    $json = json_decode($data, true);
    Assert::same($json['data'] ?? '', 'hello');
    $conn->send("world\n");
    $conn->close();
});

go(function ()  {
    $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($conn->connect('127.0.0.1', 9601));
    $conn->send(json_encode(['data' => 'hello']));
    echo $conn->recv();
});
?>
--EXPECT--
world
