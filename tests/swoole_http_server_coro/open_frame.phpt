--TEST--
swoole_http_server_coro: handle frame by user
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\CloseFrame;
use SwooleTest\ProcessManager as ProcessManager;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set([
            'open_websocket_ping_frame' => true,
            'open_websocket_pong_frame' => true,
            'open_websocket_close_frame' => true,
        ]);
        $ret = $client->upgrade('/');
        $client->push('Hello World');
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_PING);
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_PONG);
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_CLOSE);
        Assert::true($frame->code == SWOOLE_WEBSOCKET_CLOSE_NORMAL);
        Assert::true($frame->reason == "lalalala FUMEI");
        $frame = $client->recv();
        Assert::true($frame == '');
        $client->disconnect();
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->set([
            'open_websocket_ping_frame' => true,
            'open_websocket_pong_frame' => true,
            'open_websocket_close_frame' => true,
        ]);
        $server->handle('/', function (Request $request, Response $response) {
            $response->upgrade();
            $ping = new Frame();
            $ping->opcode = SWOOLE_WEBSOCKET_OPCODE_PING;
            $response->push($ping);

            $pong = new Frame();
            $pong->opcode = SWOOLE_WEBSOCKET_OPCODE_PONG;
            $response->push($pong);

            $close = new CloseFrame();
            $close->opcode = SWOOLE_WEBSOCKET_OPCODE_CLOSE;
            $close->code = SWOOLE_WEBSOCKET_CLOSE_NORMAL;
            $close->reason = "lalalala FUMEI";
            $response->push($close);
        });

        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
