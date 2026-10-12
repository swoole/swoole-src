--TEST--
swoole_socket_coro: length packets survive timeouts in fragmented headers and bodies
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;

function checkPacket(bool $condition): void
{
    if (!$condition) {
        throw new RuntimeException('Packet timeout assertion failed');
    }
}

Coroutine\run(function () {
    foreach ([2, 4, 8] as $split) {
        $listener = new Socket(AF_INET, SOCK_STREAM, 0);
        checkPacket($listener->bind('127.0.0.1', 0) && $listener->listen());
        $ready = new Channel(1);
        $resume = new Channel(1);
        $packet = pack('N', 16) . str_repeat('x', 16);
        $next = pack('N', 4) . 'next';
        Coroutine::create(function () use ($listener, $ready, $resume, $packet, $next, $split) {
            $peer = $listener->accept(2);
            checkPacket($peer instanceof Socket);
            checkPacket($peer->sendAll(substr($packet, 0, $split)) === $split);
            $ready->push(true);
            checkPacket($resume->pop(2) === true);
            $remaining = substr($packet, $split) . $next;
            checkPacket($peer->sendAll($remaining) === strlen($remaining));
            $peer->close();
        });
        $client = new Socket(AF_INET, SOCK_STREAM, 0);
        $client->setProtocol([
            'open_length_check' => true,
            'package_length_type' => 'N',
            'package_length_offset' => 0,
            'package_body_offset' => 4,
            'package_max_length' => 1024,
        ]);
        checkPacket($client->connect('127.0.0.1', $listener->getsockname()['port'], 2));
        checkPacket($ready->pop(2) === true);
        for ($i = 0; $i < 2; $i++) {
            checkPacket($client->recvPacket(0.01) === false);
            checkPacket($client->errCode === SOCKET_ETIMEDOUT);
            checkPacket(!$client->isClosed());
        }
        $resume->push(true);
        checkPacket($client->recvPacket(2) === $packet);
        checkPacket($client->recvPacket(2) === $next);
        checkPacket($client->recvPacket(2) === '');
        $client->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
