--TEST--
swoole_http_client_coro/websocket: continue frame finish flag - 2
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
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $ret = $client->upgrade('/');
        Assert::assert($ret);
        $client->push($data1, SWOOLE_WEBSOCKET_OPCODE_TEXT, 0);
        $client->push($data2, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
        $client->push($data3, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
        $frame = $client->recv();
        Assert::true($frame->data == $data1 . $data2 . $data3);
        Assert::eq($frame->opcode, SWOOLE_WEBSOCKET_OPCODE_TEXT);
        Assert::eq($frame->finish, true);
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $data1, $data2, $data3) {
    Co\run(function () use ($pm, $data1, $data2, $data3) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) use ($data1, $data2, $data3) {
            $response->upgrade();
            $frame = $response->recv();
            Assert::true($frame->data == $data1 . $data2 . $data3);
            Assert::eq($frame->opcode, SWOOLE_WEBSOCKET_OPCODE_TEXT);
            Assert::eq($frame->finish, true);
            $response->push($data1, SWOOLE_WEBSOCKET_OPCODE_TEXT, 0);
            $response->push($data2, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, 0);
            $response->push($data3, SWOOLE_WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN);
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
