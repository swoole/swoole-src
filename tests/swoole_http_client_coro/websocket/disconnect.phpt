--TEST--
swoole_http_client_coro/websocket: test disconnect function
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $ret = $client->upgrade('/');
        Assert::true($client->disconnect(SWOOLE_WEBSOCKET_CLOSE_NORMAL, 'close it'));
        Assert::true($client->connected == 0);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_websocket_close_frame' => true
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('message', function (Server $server, Frame $frame) {
        var_dump($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_CLOSE);
        var_dump($frame->reason == 'close it');
    });

    $server->on('close', function (Swoole\Server $server, int $fd, int $reactorId) {
        var_dump($reactorId);
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
bool(true)
bool(true)
int(0)
