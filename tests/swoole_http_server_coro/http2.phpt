--TEST--
swoole_http_server_coro: http2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http2\Request;
use Swoole\Http2\Response;
use Swoole\Coroutine\Http2\Client;

$pm = new SwooleTest\ProcessManager;

const N = 10;

$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());
        $streams = [];
        $request = new Request;
        for ($n = N; $n--;) {
            $request->data = $n;
            $streams[$client->send($request)] = $n;
        }
        for ($n = N; $n--;) {
            /** @var $response Response */
            $response = $client->recv();
            Assert::same($streams[$response->streamId], (int)$response->data);
        }
        echo "DONE\n";
        $kill_request = new Request;
        $kill_request->path = '/stop';
        $client->send($kill_request);
        $response = $client->recv();
        Assert::assert($response instanceof Response);
        echo $response->data, "\n";
    });
};

$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Swoole\Coroutine\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
            $response->end($request->rawContent());
        });
        $server->handle('/stop', function (Swoole\Http\Request $request, Swoole\Http\Response  $response) use ($server) {
            $response->end("STOP");
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
STOP
