--TEST--
swoole_http_client_coro/websocket: auto pong
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
        $client->push('hello world', SWOOLE_WEBSOCKET_OPCODE_TEXT);
        while ($client->recv()) {
            $client->push('hello world', SWOOLE_WEBSOCKET_OPCODE_TEXT);
        }
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_websocket_pong_frame' => true
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $data = [];
    $count = 0;
    $server->on('message', function (Server $server, Frame $frame) use ($pm, &$data, &$count) {
        if ($count == 1000) {
            $server->disconnect($frame->fd);
            for ($i = 0; $i < 1000; $i++) {
                Assert::true($data[$i]->opcode == SWOOLE_WEBSOCKET_OPCODE_PONG);
            }
            return;
        }

        if ($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_PONG) {
            $count++;
            $data[] = $frame;
        }

        $server->push($frame->fd, "hello world", SWOOLE_WEBSOCKET_OPCODE_TEXT);
        $ping = new Frame();
        $ping->data = $frame->data;
        $ping->opcode = SWOOLE_WEBSOCKET_OPCODE_PING;
        $server->push($frame->fd, $ping);
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
