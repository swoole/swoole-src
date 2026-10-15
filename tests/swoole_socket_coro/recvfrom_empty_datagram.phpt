--TEST--
swoole_socket_coro: empty datagrams preserve their source address
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
Swoole\Coroutine\run(function () {
    $receiver = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $senders = [
        new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0),
        new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0),
    ];
    try {
        $receiver->bind('127.0.0.1', 0);
        $destination = $receiver->getsockname();
        foreach ($senders as $sender) {
            $sender->bind('127.0.0.1', 0);
        }
        $peer = null;
        foreach ([[0, ''], [0, 'hello'], [1, ''], [0, ''], [1, 'tail']] as [$index, $payload]) {
            $sender = $senders[$index];
            if ($sender->sendto($destination['address'], $destination['port'], $payload) !== strlen($payload)
                || $receiver->recvfrom($peer, 1) !== $payload
                || $peer !== $sender->getsockname()) {
                throw new RuntimeException('recvfrom lost the datagram or its source address');
            }
        }
        $peer = ['sentinel'];
        if ($receiver->recvfrom($peer, 0.001) !== false || $peer !== ['sentinel']) {
            throw new RuntimeException('A failed receive changed the source address');
        }
    } finally {
        $receiver->close();
        foreach ($senders as $sender) {
            $sender->close();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
