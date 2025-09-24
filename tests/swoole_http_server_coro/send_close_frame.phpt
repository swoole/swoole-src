--TEST--
swoole_http_server_coro: send close frame will close connection - 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Response;
use Swoole\Http\Request;
use Swoole\WebSocket\CloseFrame;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $ret = $client->upgrade('/');
        $close = new CloseFrame();
        $close->opcode = SWOOLE_WEBSOCKET_OPCODE_CLOSE;
        $close->code = SWOOLE_WEBSOCKET_CLOSE_NORMAL;
        $close->reason = 'hahahhah';
        Assert::true($client->push($close));
        Assert::false($client->recv());
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->upgrade();
            Assert::true($response->recv() == '');
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
