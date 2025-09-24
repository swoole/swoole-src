--TEST--
swoole_http_client_coro: send close frame will close connection - 1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Server;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\CloseFrame;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $ret = $client->upgrade('/');
        $close = new CloseFrame();
        $close->opcode = SWOOLE_WEBSOCKET_OPCODE_CLOSE;
        $close->code = SWOOLE_WEBSOCKET_CLOSE_NORMAL;
        $close->reason = 'hahahhah';
        Assert::true($client->push($close));
        Assert::false($client->recv());
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'package_max_length' => 100 * 1024 * 1024,
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('message', function (Server $server, Frame $frame) use ($pm) {

    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
