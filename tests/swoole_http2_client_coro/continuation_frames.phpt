--TEST--
swoole_http2_client_coro: parse header blocks continued in CONTINUATION frames
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;

const END_STREAM  = 0x1;
const END_HEADERS = 0x4;

function http2_connect(): array
{
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    Assert::true($client->connect());
    $peer = $listener->accept(1);
    Assert::isInstanceOf($peer, Socket::class);
    $listener->close();
    http2_send($peer, http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0));
    return [$client, $peer];
}

function http2_send(Socket $peer, string $frames): void
{
    Assert::same($peer->sendAll($frames), strlen($frames));
}

Swoole\Coroutine\run(function () {
    [$client, $peer] = http2_connect();

    // ":status: 200" and "x-a: b", which goes into the dynamic table, split inside the second field
    Assert::same($client->send(new Request()), 1);
    http2_send(
        $peer,
        http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, END_STREAM, 1, "\x88\x40\x03x")
            . http2_test_frame(SWOOLE_HTTP2_TYPE_CONTINUATION, 0, 1, '-a')
            . http2_test_frame(SWOOLE_HTTP2_TYPE_CONTINUATION, END_HEADERS, 1, "\x01b")
    );
    $response = $client->recv(1);
    Assert::same($response->streamId, 1);
    Assert::same($response->statusCode, 200);
    Assert::same($response->headers, ['x-a' => 'b']);

    // The next block refers to the dynamic table entry
    Assert::same($client->send(new Request()), 3);
    http2_send($peer, http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, END_HEADERS | END_STREAM, 3, "\x88\xbe"));
    $response = $client->recv(1);
    Assert::same($response->streamId, 3);
    Assert::same($response->headers, ['x-a' => 'b']);

    // A pipelined response doesn't return a trailer block before it is complete
    Assert::same($client->send(new Request()), 5);
    http2_send(
        $peer,
        http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, END_HEADERS, 5, "\x88")
            . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, 0, 5, 'abc')
            . http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, END_STREAM, 5, "\x00\x03x-t")
            . http2_test_frame(SWOOLE_HTTP2_TYPE_CONTINUATION, END_HEADERS, 5, "\x01t")
    );
    $response = $client->read(1);
    Assert::same($response->data, 'abc');
    Assert::true($response->pipeline);
    $response = $client->read(1);
    Assert::same($response->headers, ['x-t' => 't']);
    Assert::false($response->pipeline);

    $client->close();
    $peer->close();

    // RFC 9113 §6.10: CONTINUATION frames only follow an unfinished header block, on its stream, with nothing between
    $open = http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, 0, 1, "\x88");
    foreach ([
        http2_test_frame(SWOOLE_HTTP2_TYPE_CONTINUATION, END_HEADERS, 1),
        http2_test_frame(SWOOLE_HTTP2_TYPE_CONTINUATION, END_HEADERS, 0),
        $open . http2_test_frame(SWOOLE_HTTP2_TYPE_CONTINUATION, END_HEADERS, 3),
        $open . http2_test_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, str_repeat("\0", 8)),
    ] as $frames) {
        [$client, $peer] = http2_connect();
        Assert::same($client->send(new Request()), 1);
        http2_send($peer, $frames);
        Assert::false($client->recv(1));
        Assert::false($client->connected);
        Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR);
        $peer->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
