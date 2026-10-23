--TEST--
swoole_http_client_coro/websocket: token parser errors must reject the handshake
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;

Assert::setThrowException(true);

function readRequest(Socket $socket): string
{
    $request = '';
    while (!str_contains($request, "\r\n\r\n")) {
        $data = $socket->recv(8192, 2);
        Assert::notEmpty($data);
        $request .= $data;
    }
    return $request;
}

function checkHandshake(string $upgrade, string $connection, bool $expected): void
{
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $done = new Channel(1);
    Coroutine::create(function () use ($listener, $done, $upgrade, $connection) {
        $peer = $listener->accept(2);
        Assert::isInstanceOf($peer, Socket::class);
        try {
            readRequest($peer);
            $peer->sendAll("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n", 2);
            Assert::same($peer->recvAll(4, 2), 'grow');
            Assert::same($peer->sendAll('head', 2), 4);
            $request = readRequest($peer);
            Assert::same(preg_match('/Sec-WebSocket-Key: ([^\r\n]+)/i', $request, $matches), 1);
            $accept = base64_encode(sha1($matches[1] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
            $response = "HTTP/1.1 101 Switching Protocols\r\n"
                . "Upgrade: $upgrade\r\nConnection: $connection\r\nSec-WebSocket-Accept: $accept\r\n\r\n";
            Assert::same($peer->sendAll($response, 2), strlen($response));
            Assert::same($peer->recv(1, 2), '');
        } finally {
            $peer->close();
            $done->push(true);
        }
    });

    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $client->set(['timeout' => 2]);
    try {
        Assert::true($client->get('/warmup'));
        $socket = $client->socket;
        $calls = 0;
        // A default HTTP response buffer would reject these headers before token parsing.
        // A partial length-framed read grows it to 128 KiB. The next failed length
        // lookup clears the partial bytes while retaining the enlarged allocation.
        Assert::true($socket->setProtocol([
            'open_length_check' => true,
            'package_max_length' => 128 * 1024,
            'package_length_func' => function (string $data) use (&$calls): int {
                return ++$calls === 1 ? 128 * 1024 : -1;
            },
        ]));
        Assert::same($socket->sendAll('grow', 2), 4);
        Assert::false($socket->recvPacket(0.01));
        Assert::same($socket->errCode, SOCKET_ETIMEDOUT);
        Assert::same($socket->recvPacket(2), '');
        Assert::same($calls, 2);
        Assert::true($socket->setProtocol(['open_length_check' => false]));

        Assert::same($client->upgrade('/'), $expected);
        if ($expected) {
            Assert::same($client->statusCode, 101);
            Assert::same($client->errCode, 0);
        } else {
            Assert::same($client->errCode, SWOOLE_ERROR_WEBSOCKET_HANDSHAKE_FAILED);
            Assert::false($client->connected);
        }
    } finally {
        $client->close();
        Assert::true($done->pop(2));
        $listener->close();
    }
}

Coroutine\run(function () {
    // The token parser accepts at most 65535 bytes, including any matching token.
    $upgrade = 'websocket, ';
    checkHandshake($upgrade . str_repeat('x', 65535 - strlen($upgrade)), 'Upgrade', true);
    checkHandshake($upgrade . str_repeat('x', 65536 - strlen($upgrade)), 'Upgrade', false);
    $connection = 'keep-alive, UpGrAdE, ';
    checkHandshake('websocket', $connection . str_repeat('x', 65535 - strlen($connection)), true);
    checkHandshake('websocket', $connection . str_repeat('x', 65536 - strlen($connection)), false);
    checkHandshake('websocket', str_repeat('x', 65536), false);
    checkHandshake('websocket', str_repeat('x', 65537), false);
    checkHandshake('h2c', 'Upgrade', false);
    checkHandshake('websocket', 'keep-alive', false);
    checkHandshake('other, WebSocket', 'keep-alive, UpGrAdE', true);
});
echo "DONE\n";
?>
--EXPECT--
DONE
