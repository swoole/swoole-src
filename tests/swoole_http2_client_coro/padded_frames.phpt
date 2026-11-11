--TEST--
swoole_http2_client_coro: discard the padding of HEADERS and DATA frames
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('zlib');
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;

const END_STREAM  = 0x1;
const END_HEADERS = 0x4;
const PADDED      = 0x8;
const PRIORITY    = 0x20;

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
    Assert::same($client->send(new Request()), 1);
    return [$client, $peer];
}

function http2_send(Socket $peer, string $frames): void
{
    Assert::same($peer->sendAll($frames), strlen($frames));
}

Swoole\Coroutine\run(function () {
    // Padded HEADERS with priority fields, then padded DATA, the last frame all padding
    [$client, $peer] = http2_connect();
    http2_send(
        $peer,
        http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, PADDED | PRIORITY | END_HEADERS, 1, "\x02\0\0\0\0\x10\x88\0\0")
            . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, PADDED, 1, "\x03abc\0\0\0")
            . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, PADDED, 1, "\x00def")
            . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, PADDED | END_STREAM, 1, "\x02\0\0")
    );
    $response = $client->recv(1);
    Assert::same($response->statusCode, 200);
    Assert::same($response->data, 'abcdef');
    $client->close();
    $peer->close();

    // An all-padding frame must not reach the gzip decoder
    [$client, $peer] = http2_connect();
    $body            = gzencode('hello');
    http2_send(
        $peer,
        http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, END_HEADERS, 1, "\x88\x5a\x04gzip")
            . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, PADDED, 1, "\x02{$body}\0\0")
            . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, PADDED | END_STREAM, 1, "\x02\0\0")
    );
    $response = $client->recv(1);
    Assert::same($response->data, 'hello');
    $client->close();
    $peer->close();

    // The padding still counts against the flow-control windows: 49162 bytes of a 65535-byte window crosses the
    // client's quarter-window threshold, but the 48384 body bytes alone don't
    [$client, $peer] = http2_connect();
    $padded          = "\xff" . str_repeat('a', 16128) . str_repeat("\0", 255);
    http2_send(
        $peer,
        http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, END_HEADERS, 1, "\x88")
            . str_repeat(http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, PADDED, 1, $padded), 3)
            . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, PADDED | END_STREAM, 1, "\x09" . str_repeat("\0", 9))
    );
    $response = $client->recv(1);
    Assert::same($response->data, str_repeat('a', 48384));
    $client->close();
    $received = '';
    while (is_string($data = $peer->recv(65536, 1)) && $data !== '') {
        $received .= $data;
    }
    $peer->close();
    $increments = [];
    for ($offset = 24; $offset < strlen($received); $offset += 9 + $length) {
        $length = unpack('N', "\0" . substr($received, $offset, 3))[1];
        if (ord($received[$offset + 3]) === SWOOLE_HTTP2_TYPE_WINDOW_UPDATE) {
            $increments[unpack('N', substr($received, $offset + 5, 4))[1]] = unpack('N', substr($received, $offset + 9, 4))[1];
        }
    }
    Assert::same($increments, [0 => 49162, 1 => 49162]);

    foreach ([
        // Padding at least as long as the payload
        [http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, PADDED | END_HEADERS, 1), SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR],
        [http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, PADDED | END_HEADERS, 1, "\x02\x88"), SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR],
        [
            http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, END_HEADERS, 1, "\x88")
                . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, PADDED | END_STREAM, 1, "\x04abc"),
            SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR,
        ],
        // Too short for the priority fields
        [http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, PRIORITY | END_HEADERS, 1, "\x88\0"), SWOOLE_HTTP2_ERROR_FRAME_SIZE_ERROR],
        [
            http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, PADDED | PRIORITY | END_HEADERS, 1, "\x01\0\0\0\0\x10"),
            SWOOLE_HTTP2_ERROR_FRAME_SIZE_ERROR,
        ],
    ] as [$frames, $errCode]) {
        [$client, $peer] = http2_connect();
        http2_send($peer, $frames);
        Assert::false($client->recv(1));
        Assert::false($client->connected);
        Assert::same($client->errCode, $errCode);
        $peer->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
