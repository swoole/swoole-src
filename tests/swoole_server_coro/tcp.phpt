--TEST--
swoole_server_coro: tcp
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';


use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

go(function () {

    $server = new Server('0.0.0.0', 9601, false);

    $server->handle(function (Connection $conn) use ($server) {
        $data = $conn->recv();
        $json = json_decode($data, true);
        Assert::same($json['data'] ?? '', 'hello');
        $conn->send("world\n");
        $conn->close();

        $server->shutdown();
    });

    $server->start();
});

go(function () {
    $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($conn->connect('127.0.0.1', 9601));
    $conn->send(json_encode(['data' => 'hello']));
    echo $conn->recv();
});

swoole_event::wait();
?>
--EXPECT--
world
