--TEST--
swoole_http_client_coro/websocket: send more continue frames - coroutine websocket server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Coroutine\Http\Server;
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
        $client->set(['websocket_compression' => true]);
        $ret = $client->upgrade('/');
        Assert::assert($ret);
        $client->push('111', SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_FIN);
        $frame = $client->recv();
        Assert::true($frame->data == $data1 . $data2 . $data2 . $data2 . $data3);
        $frame = $client->recv();
        Assert::true($frame->data == $data2 . $data1 . $data3);
        $frame = $client->recv();
        Assert::true($frame->data == $data3 . $data2 . $data1);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $data1, $data2, $data3) {
    Co\run(function () use ($pm, $data1, $data2, $data3) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->set(['websocket_compression' => true]);
        $server->handle('/', function ($request, $response) use ($data1, $data2, $data3) {
            $response->upgrade();
            $frame = $response->recv();
                    $context = deflate_init(ZLIB_ENCODING_RAW);
                    $response->push(deflate_add($context, $data1, ZLIB_SYNC_FLUSH), SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_COMPRESS | SWOOLE_WEBSOCKET_FLAG_RSV1);
                    $response->push(deflate_add($context, $data2, ZLIB_SYNC_FLUSH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
                    $response->push(deflate_add($context, $data2, ZLIB_SYNC_FLUSH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
                    $response->push(deflate_add($context, $data2, ZLIB_SYNC_FLUSH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
                    $response->push(deflate_add($context, $data3, ZLIB_FINISH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);

                    $response->push(deflate_add($context, $data2, ZLIB_NO_FLUSH), SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_COMPRESS | SWOOLE_WEBSOCKET_FLAG_RSV1);
                    $response->push(deflate_add($context, $data1, ZLIB_NO_FLUSH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
                    $response->push(deflate_add($context, $data3, ZLIB_FINISH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);

                    $response->push(deflate_add($context, $data3, ZLIB_NO_FLUSH), SWOOLE_WEBSOCKET_OPCODE_TEXT, SWOOLE_WEBSOCKET_FLAG_COMPRESS | SWOOLE_WEBSOCKET_FLAG_RSV1);
                    $response->push(deflate_add($context, $data2, ZLIB_NO_FLUSH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
                    $response->push(deflate_add($context, $data1, ZLIB_FINISH), SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
