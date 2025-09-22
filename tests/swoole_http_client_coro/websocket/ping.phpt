--TEST--
swoole_http_client_coro: test ping function
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
        $client->set(['open_websocket_pong_frame' => true]);
        $ret = $client->upgrade('/');
        Assert::true($client->ping());
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_PONG);
        Assert::true($frame->data == '');
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('message', function (Server $server, Frame $frame) {
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
