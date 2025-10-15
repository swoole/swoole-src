--TEST--
swoole_http_client_coro/websocket: client continue frames - 4
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use SwooleTest\ProcessManager as ProcessManager;

$data1 = bin2hex(random_bytes(10 * 1024));
$data2 = bin2hex(random_bytes(20 * 2048));
$data3 = bin2hex(random_bytes(40 * 4096));

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, $data1, $data2, $data3) {
    Co\run(function () use ($pm, $data1, $data2, $data3) {
        $results = [];
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $ret = $client->upgrade('/');
        Assert::assert($ret);
        $client->push('111', SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_FIN);
        $results[] = $client->recv();
        Assert::true($results[0]->data == $data1 . $data2 . $data3);
        $client->push('222', SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_FIN);
        $results[] = $client->recv();
        Assert::true($results[1]->data == $data3 . $data2 . $data1);
        Assert::true($results[0]->data != $results[1]->data);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $data1, $data2, $data3) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'package_max_length' => 100 * 1024 * 1024,
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('message', function (Server $server, Frame $frame) use ($pm, $data1, $data2, $data3) {
        if ($frame->data == '111') {
            $server->push($frame->fd, $data1, SWOOLE_WEBSOCKET_OPCODE_TEXT, 0);
            $server->push($frame->fd, $data2, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
            $server->push($frame->fd, $data3, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
        } else {
            $server->push($frame->fd, $data3, SWOOLE_WEBSOCKET_OPCODE_TEXT, 0);
            $server->push($frame->fd, $data2, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
            $server->push($frame->fd, $data1, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
        }
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
