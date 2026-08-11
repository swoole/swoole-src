--TEST--
swoole_http_client_coro/websocket: compression negotiation is independent of response header order
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $client->set([
            'websocket_compression' => true,
        ]);
        Assert::true($client->upgrade('/'));
        Assert::true($client->push(
            'compressed request',
            SWOOLE_WEBSOCKET_OPCODE_TEXT,
            SWOOLE_WEBSOCKET_FLAG_FIN
        ));
        Assert::same($client->recv()->data, 'OK');
        $client->close();
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'websocket_compression' => true,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('handshake', function (Request $request, Response $response) {
        $accept = base64_encode(sha1(
            $request->header['sec-websocket-key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11',
            true
        ));
        // The extension must precede Upgrade to exercise order-independent negotiation.
        $response->header('Sec-WebSocket-Extensions', 'permessage-deflate');
        $response->header('Upgrade', 'websocket');
        $response->header('Connection', 'Upgrade');
        $response->header('Sec-WebSocket-Accept', $accept);
        $response->header('Sec-WebSocket-Version', '13');
        $response->status(101);
        $response->end();
        return true;
    });
    $server->on('message', function (Server $server, Frame $frame) {
        Assert::same($frame->data, 'compressed request');
        Assert::true((bool) ($frame->flags & SWOOLE_WEBSOCKET_FLAG_COMPRESS));
        $server->push($frame->fd, 'OK');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
