--TEST--
swoole_client_coro: close in other coroutine
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$cid = go(function () {
    $sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($sock->bind('127.0.0.1', 9601));
    Assert::assert($sock->listen(512));
    $conn = $sock->accept();
    Assert::assert($conn);
    Assert::isInstanceOf($conn, Swoole\Coroutine\Socket::class);
    Co::yield();
});

$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);

go(function () use ($client) {
    $client->connect('127.0.0.1', 9601);
    $data = @$client->recv();
    //socket is closed
    Assert::assert(!$data && $client->errCode === SOCKET_ECONNRESET);
});

go(function () use ($client, $cid) {
    co::sleep(.01);
    $client->close();
    co::sleep(.01);
    co::resume($cid);
});

swoole_event_wait();
echo "DONE\n";
?>
--EXPECT--
DONE
