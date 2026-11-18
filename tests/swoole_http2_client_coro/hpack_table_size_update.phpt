--TEST--
swoole_http2_client_coro: accept an HPACK table size update between response header blocks
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;
use Swoole\Http2\Response;

Swoole\Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    Assert::true($client->connect());
    $peer = $listener->accept(2);
    Assert::isInstanceOf($peer, Socket::class);
    $listener->close();

    $settings = http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0);
    Assert::same($peer->sendAll($settings), strlen($settings));

    $blocks = [
        // :status = 200, then insert x-a: b into the dynamic table.
        1 => ["\x88\x40\x03x-a\x01b", ['x-a' => 'b']],
        // Reference the same dynamic table entry from the next response.
        3 => ["\x88\xbe", ['x-a' => 'b']],
        // Shrink the dynamic table to zero at the start of a fresh header block.
        5 => ["\x20\x88", []],
    ];
    foreach ($blocks as $streamId => [$block, $headers]) {
        Assert::same($client->send(new Request()), $streamId);
        $frame = http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, 0x5, $streamId, $block);
        Assert::same($peer->sendAll($frame), strlen($frame));
        $response = $client->recv(2);
        if (!$response instanceof Response) {
            throw new RuntimeException($client->errMsg);
        }
        Assert::same($response->streamId, $streamId);
        Assert::same($response->statusCode, 200);
        Assert::same($response->headers, $headers);
        Assert::same($response->trailers, null);
    }

    $client->close();
    $peer->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
