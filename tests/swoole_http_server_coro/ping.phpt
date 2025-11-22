--TEST--
swoole_http_server_coro: test ping function
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->set(['open_websocket_ping_frame' => true]);
        Assert::true($client->upgrade('/'));
        Assert::true($client->push('Hello World'));
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_PING);
        Assert::true($frame->data == 'Hello World');
        Assert::true($client->ping());
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_PING);
        Assert::true($frame->data == '');
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->upgrade();
            $response->recv();
            $response->ping('Hello World');
            $response->ping();
        });
        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
