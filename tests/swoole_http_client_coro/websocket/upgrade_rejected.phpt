--TEST--
swoole_http_client_coro/websocket: upgrade requires a valid HTTP 101 handshake
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\WebSocket\Frame;

Assert::setThrowException(true);

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $server->handle('/reject', function ($request, $response) {
        $status = (int) $request->get['status'];
        $response->status($status);
        $response->header('X-Rejected', 'yes');
        // An Upgrade header alone must not make a non-101 response successful.
        $response->header('Upgrade', 'websocket');
        $response->end("rejected: $status");
    });
    $server->handle('/missing-headers', function ($request, $response) {
        $response->status(101);
        $response->end();
    });
    $server->handle('/invalid-accept', function ($request, $response) {
        $response->status(101);
        $response->header('Upgrade', 'websocket');
        $response->header('Connection', 'Upgrade');
        $response->header('Sec-WebSocket-Accept', 'invalid');
        $response->end();
    });
    $server->handle('/websocket', function ($request, $response) {
        Assert::true($response->upgrade());
        $frame = $response->recv(2);
        Assert::isInstanceOf($frame, Frame::class);
        Assert::true($response->push($frame->data));
        $response->close();
    });
    Coroutine::create(fn () => $server->start());

    $client = new Client('127.0.0.1', $server->port);
    $client->set(['timeout' => 2]);
    try {
        foreach ([200, 302, 403, 404, 500] as $status) {
            Assert::false($client->upgrade('/reject?status=' . $status));
            Assert::same($client->statusCode, $status);
            Assert::same($client->headers['x-rejected'], 'yes');
            Assert::same($client->body, "rejected: $status");
            Assert::same($client->errCode, SWOOLE_ERROR_WEBSOCKET_HANDSHAKE_FAILED);
            Assert::notEmpty($client->errMsg);
        }
        foreach (['/missing-headers', '/invalid-accept'] as $path) {
            Assert::false($client->upgrade($path));
            Assert::same($client->errCode, SWOOLE_ERROR_WEBSOCKET_HANDSHAKE_FAILED);
        }
        // A failed handshake must not prevent a subsequent valid upgrade.
        Assert::true($client->upgrade('/websocket'));
        Assert::same($client->statusCode, 101);
        Assert::same($client->errCode, 0);
        Assert::same($client->errMsg, '');
        Assert::true($client->push('hello'));
        $frame = $client->recv(2);
        Assert::isInstanceOf($frame, Frame::class);
        Assert::same($frame->data, 'hello');
    } finally {
        $client->close();
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
