--TEST--
swoole_http_client_coro/websocket: open websocket frame
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
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set([
            'open_websocket_ping_frame' => true,
            'open_websocket_pong_frame' => true,
            'open_websocket_close_frame' => true,
        ]);
        $ret = $client->upgrade('/');
        Assert::assert($ret);
        $client->push('Hello World!!!');
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_PING);
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_PONG);
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_CLOSE);
        $frame = $client->recv();
        Assert::true($frame == '');
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $data1, $data2, $data3) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set([
        'package_max_length' => 100 * 1024 * 1024,
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('message', function (Server $server, Frame $frame) use ($pm, $data1, $data2, $data3) {
        Assert::true($frame->data == 'Hello World!!!');
        $ping = new Frame();
        $ping->opcode = SWOOLE_WEBSOCKET_OPCODE_PING;
        $server->push($frame->fd, $ping);

        $pong = new Frame();
        $pong->opcode = SWOOLE_WEBSOCKET_OPCODE_PONG;
        $server->push($frame->fd, $pong);

        $server->disconnect($frame->fd);
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
