--TEST--
swoole_http_server_coro: test disconnect function
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
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
            'open_websocket_close_frame' => true
        ]);
        $ret = $client->upgrade('/');
        $client->push('Hello World');
        $frame = $client->recv();
        Assert::true($frame->opcode == SWOOLE_WEBSOCKET_OPCODE_CLOSE);
        Assert::true($frame->reason == 'close it');
        Assert::true($client->recv() == '');
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle('/', function (Request $request, Response $response) {
            $response->upgrade();
            $response->recv();
            Assert::true($response->disconnect(SWOOLE_WEBSOCKET_CLOSE_NORMAL, 'close it'));
        });

        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
