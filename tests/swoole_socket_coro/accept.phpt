--TEST--
swoole_socket_coro: accept
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/lib/curl.php';

go(function () {
    $sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    assert($sock->bind('127.0.0.1', 9601));
    assert($sock->listen(512));
    $conn = $sock->accept();
    assert($conn);
    assert($conn instanceof Swoole\Coroutine\Socket);

    $data = $conn->recv();
    $json = json_decode($data, true);
    assert(is_array($json), $json['data'] == 'hello');
    $conn->send("world\n");
    $conn->close();
});

go(function ()  {
    $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    assert($conn->connect('127.0.0.1', 9601));
    $conn->send(json_encode(['data' => 'hello']));
    echo $conn->recv();
});
?>
--EXPECT--
world
