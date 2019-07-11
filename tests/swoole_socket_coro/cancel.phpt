--TEST--
swoole_socket_coro: cancel
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
$socket->bind('127.0.0.1', 9601);
//Server
go(function () use ($socket) {
    while (true) {
        $peer = null;
        $data = $socket->recvfrom($peer);
        Assert::assert(empty($data));
        Assert::assert($socket->errCode == SOCKET_ECANCELED);
        break;
    }
    echo "DONE\n";
});

//Client
go(function () use ($socket) {
    co::sleep(0.1);
    $socket->cancel();
});
swoole_event_wait();
?>
--EXPECT--
DONE
