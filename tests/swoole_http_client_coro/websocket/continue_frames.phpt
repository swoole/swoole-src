--TEST--
swoole_http_client_coro: client continue frames
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use SwooleTest\ProcessManager as ProcessManager;

$data1 = str_repeat('a', 1024 * 1024);
$data2 = str_repeat('b', 2048 * 2048);
$data3 = str_repeat('c', 4086 * 4086);

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, $data1, $data2, $data3) {
    Co\run(function () use ($pm, $data1, $data2, $data3) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set(['websocket_compression' => true]);
        $ret = $client->upgrade('/');
        Assert::assert($ret);
        $inflator = deflate_init(ZLIB_ENCODING_RAW);
        $client->push(deflate_add($inflator, $data1, ZLIB_NO_FLUSH), SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_RSV1);
        $client->push(deflate_add($inflator, $data2, ZLIB_NO_FLUSH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
        $client->push(deflate_add($inflator, $data3, ZLIB_FINISH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
        $frame = $client->recv();
        Assert::true($frame->data == $data1 . $data2 . $data3);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $data1, $data2, $data3) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set([
        'log_file' => '/dev/null',
        'websocket_compression' => true
    ]);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('message', function (Server $server, Frame $frame) use ($pm, $data1, $data2, $data3) {
        Assert::true($frame->data == $data1 . $data2 . $data3);
        $inflator = deflate_init(ZLIB_ENCODING_RAW);
        $server->push($frame->fd, deflate_add($inflator, $data1, ZLIB_NO_FLUSH), SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_RSV1);
        $server->push($frame->fd, deflate_add($inflator, $data2, ZLIB_NO_FLUSH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
        $server->push($frame->fd, deflate_add($inflator, $data3, ZLIB_FINISH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
    });

    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
