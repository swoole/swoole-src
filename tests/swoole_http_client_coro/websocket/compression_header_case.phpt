--TEST--
swoole_http_client_coro/websocket: compression negotiation preserves response header casing
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $client->set([
            'lowercase_header' => false,
            'websocket_compression' => true,
        ]);
        Assert::true($client->upgrade('/'));
        Assert::keyExists($client->getHeaders(), 'Sec-Websocket-Extensions');
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
