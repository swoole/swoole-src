--TEST--
swoole_http2_client_coro: echo PING payloads and reject PING frames of the wrong length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;

const HTTP2_FLAG_ACK = 0x1;

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7fffffff)
        . $payload;
}

function http2_exchange(?string $frame, callable $test): string
{
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    Assert::true($client->connect());
    $peer = $listener->accept(1);
    Assert::isInstanceOf($peer, Socket::class);
    if ($frame !== null) {
        Assert::same($peer->sendAll($frame), strlen($frame));
    }
    $test($client);
    $client->close();
    $received = $peer->recvAll(65535, 1);
    $peer->close();
    $listener->close();
    return $received;
}

Swoole\Coroutine\run(function () {
    $received = http2_exchange(http2_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'ABCDEFGH'), function (Client $client) {
        Assert::false($client->recv(0.1));
        Assert::same($client->errCode, SOCKET_ETIMEDOUT);
    });
    Assert::contains($received, http2_frame(SWOOLE_HTTP2_TYPE_PING, HTTP2_FLAG_ACK, 0, 'ABCDEFGH'));

    $received = http2_exchange(null, function (Client $client) {
        Assert::true($client->ping());
    });
    Assert::contains($received, http2_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, str_repeat("\0", 8)));

    $invalidFrames = [
        http2_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'ABCDEFG'),
        http2_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'ABCDEFGHI'),
        http2_frame(SWOOLE_HTTP2_TYPE_PING, HTTP2_FLAG_ACK, 0, 'ABCDEFG'),
    ];
    foreach ($invalidFrames as $frame) {
        $received = http2_exchange($frame, function (Client $client) {
            Assert::false($client->recv(1));
            Assert::false($client->connected);
            Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_FRAME_SIZE_ERROR);
        });
        Assert::notContains($received, "\0\0\x08" . chr(SWOOLE_HTTP2_TYPE_PING) . chr(HTTP2_FLAG_ACK));
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
