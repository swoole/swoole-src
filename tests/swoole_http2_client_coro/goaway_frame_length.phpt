--TEST--
swoole_http2_client_coro: reject GOAWAY frames too short for their fields
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7fffffff)
        . $payload;
}

function http2_receive(string $frame): Client
{
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    Assert::true($client->connect());
    $peer = $listener->accept(1);
    Assert::isInstanceOf($peer, Socket::class);
    Assert::same($peer->sendAll($frame), strlen($frame));
    Assert::false($client->recv(1));
    Assert::false($client->connected);
    $peer->close();
    $listener->close();
    return $client;
}

Swoole\Coroutine\run(function () {
    foreach (['', 'ABCDEFG'] as $payload) {
        $client = http2_receive(http2_frame(SWOOLE_HTTP2_TYPE_GOAWAY, 0, 0, $payload));
        Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_FRAME_SIZE_ERROR);
    }

    foreach (['', 'bye'] as $debugData) {
        $payload = pack('NN', 1, SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM) . $debugData;
        $client = http2_receive(http2_frame(SWOOLE_HTTP2_TYPE_GOAWAY, 0, 0, $payload));
        Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM);
        Assert::same($client->errMsg, $debugData);
        Assert::same($client->serverLastStreamId, 1);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
