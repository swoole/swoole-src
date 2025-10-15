--TEST--
swoole_http_client_coro/websocket: control frame can not compress
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\CloseFrame;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set(['websocket_compression' => true]);
        $ret = $client->upgrade('/');
        Assert::assert($ret);

		$closeFrame = new CloseFrame();
        $closeFrame->opcode = SWOOLE_WEBSOCKET_OPCODE_CLOSE;
        $closeFrame->code = SWOOLE_WEBSOCKET_CLOSE_NORMAL;
        $closeFrame->reason = 'hahahahaha';
        $closeFrame->flags = 0;
        $client->push($closeFrame, SWOOLE_WEBSOCKET_FLAG_RSV1 | SWOOLE_WEBSOCKET_FLAG_COMPRESS);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set([
        'websocket_compression' => true,
        'open_websocket_close_frame' => true,
        'package_max_length' => 300 * 1024 * 1024,
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('message', function (Server $server, Frame $frame) use ($pm) {
        Assert::true(($frame->flags & SWOOLE_WEBSOCKET_FLAG_RSV1) == 0);
        Assert::true(($frame->flags & SWOOLE_WEBSOCKET_FLAG_COMPRESS) == 0);
        Assert::true(($frame->flags & SWOOLE_WEBSOCKET_FLAG_FIN) == 1);
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_CLOSE);
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
