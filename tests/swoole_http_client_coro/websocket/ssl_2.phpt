--TEST--
swoole_http_client_coro/websocket: receive multiple frames over TLS
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\WebSocket\Frame;

Assert::setThrowException(true);

Coroutine\run(function () {
    $messages = ['welcome', str_repeat('A', 16 * 1024 + 1), str_repeat('B', 64 * 1024 + 1)];
    $server = new Server('127.0.0.1', 0, true);
    $server->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $server->handle('/websocket', function ($request, $response) use ($messages) {
        Assert::true($response->upgrade());
        try {
            $frame = $response->recv(2);
            Assert::isInstanceOf($frame, Frame::class);
            Assert::same($frame->data, 'start');
            foreach ($messages as $message) {
                Assert::true($response->push($message));
            }
        } finally {
            $response->close();
        }
    });
    Coroutine::create(fn () => $server->start());

    $client = new Client('127.0.0.1', $server->port, true);
    $client->set(['timeout' => 2, 'websocket_compression' => false]);
    try {
        Assert::true($client->upgrade('/websocket'));
        Assert::same($client->getStatusCode(), 101);
        Assert::true($client->push('start'));
        // Back-to-back frames include payloads spanning multiple TLS records.
        foreach ($messages as $message) {
            $frame = $client->recv(2);
            Assert::isInstanceOf($frame, Frame::class);
            Assert::same($frame->opcode, SWOOLE_WEBSOCKET_OPCODE_TEXT);
            Assert::same($frame->data, $message);
        }
        Assert::same($client->recv(2), '');
        Assert::false($client->recv(2));
    } finally {
        $client->close();
        $server->shutdown();
    }
    echo "FINISH\n";
});
?>
--EXPECT--
FINISH
