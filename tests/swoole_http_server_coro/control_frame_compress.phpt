--TEST--
swoole_http_server_coro: control frame can not compress
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\CloseFrame;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set([
            'websocket_compression' => true,
            'open_websocket_close_frame' => true,
        ]);
        $ret = $client->upgrade('/');
        Assert::assert($ret);

        $client->push('A');
        $frame = $client->recv();
        Assert::true(($frame->flags & SWOOLE_WEBSOCKET_FLAG_RSV1) == 0);
        Assert::true(($frame->flags & SWOOLE_WEBSOCKET_FLAG_COMPRESS) == 0);
        Assert::true($frame->flags == SWOOLE_WEBSOCKET_FLAG_FIN);
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_CLOSE);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->set(['websocket_compression' => true]);
        $server->handle('/', function ($request, $response) {
            $response->upgrade();
            $closeFrame = new CloseFrame();
            $closeFrame->opcode = SWOOLE_WEBSOCKET_OPCODE_CLOSE;
            $closeFrame->code = SWOOLE_WEBSOCKET_CLOSE_NORMAL;
            $closeFrame->reason = 'hahahahaha';
            $response->push($closeFrame, SWOOLE_WEBSOCKET_FLAG_RSV1 | SWOOLE_WEBSOCKET_FLAG_COMPRESS);
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
