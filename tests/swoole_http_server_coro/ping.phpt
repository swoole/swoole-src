--TEST--
swoole_http_server_coro: test ping function
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set(['open_websocket_ping_frame' => true]);
        Assert::true($client->upgrade('/'));
        Assert::true($client->push('Hello World'));
        $frame = $client->recv();
        Assert::same($frame->opcode, SWOOLE_WEBSOCKET_OPCODE_PING);
        Assert::same($frame->data, str_repeat('A', 125));
        $frame = $client->recv();
        Assert::same($frame->opcode, SWOOLE_WEBSOCKET_OPCODE_PING);
        Assert::same($frame->data, 'Hello World');
        Assert::true($client->ping());
        $frame = $client->recv();
        Assert::same($frame->opcode, SWOOLE_WEBSOCKET_OPCODE_PING);
        Assert::same($frame->data, '');
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->upgrade();
            $response->recv();
            Assert::false($response->ping(str_repeat('A', 126)));
            Assert::same(swoole_last_error(), SWOOLE_ERROR_WEBSOCKET_PACK_FAILED);
            Assert::true($response->ping(str_repeat('A', 125)));
            Assert::true($response->ping('Hello World'));
            Assert::true($response->ping());
        });
        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	WARNING	websocket::encode(): invalid websocket control frame: opcode=9, fin=1, payload_length=126
