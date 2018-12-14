--TEST--
swoole_client_coro: close in other coroutine
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cid = go(function () {
    $sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    assert($sock->bind('127.0.0.1', 9601));
    assert($sock->listen(512));
    $conn = $sock->accept();
    assert($conn);
    assert($conn instanceof Swoole\Coroutine\Socket);
    Co::yield();
});

$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);

go(function () use ($client) {
    $client->connect('127.0.0.1', 9601);
    $data = $client->recv();
    //socket is closed
    assert($data === "");
});

go(function () use ($client, $cid) {
    co::sleep(.01);
    $client->close();
    co::sleep(.01);
    co::resume($cid);
});

swoole_event_wait();
?>
--EXPECT--
