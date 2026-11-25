--TEST--
swoole_socket_coro: EOF packets survive timeouts across the delimiter
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

function checkPacket(bool $condition): void
{
    if (!$condition) {
        throw new RuntimeException('EOF packet timeout assertion failed');
    }
}

Coroutine\run(static function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    checkPacket($listener->bind('127.0.0.1', 0) && $listener->listen());

    $client = new Socket(AF_INET, SOCK_STREAM, 0);
    $client->setProtocol(['open_eof_check' => true, 'package_eof' => "\r\n"]);
    checkPacket($client->connect('127.0.0.1', $listener->getsockname()['port'], 2));
    $peer = $listener->accept(2);
    checkPacket($peer instanceof Socket);

    checkPacket($peer->sendAll("hello\r") === 6);
    for ($i = 0; $i < 2; $i++) {
        checkPacket($client->recvPacket(0.01) === false);
        checkPacket($client->errCode === SOCKET_ETIMEDOUT);
        checkPacket(!$client->isClosed());
    }

    $remaining = "\nnext\r\ntruncated";
    checkPacket($peer->sendAll($remaining) === strlen($remaining));
    $peer->close();

    checkPacket($client->recvPacket(2) === "hello\r\n");
    checkPacket($client->recvPacket(2) === "next\r\n");
    checkPacket($client->recvPacket(2) === '');
    $client->close();
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
