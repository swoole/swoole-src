--TEST--
swoole_http2_client_coro: number
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Http\Server;
use Swoole\Http2\Request;
use Swoole\Http2\Response;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());
        $streams = [];
        $request = new Request;
        for ($n = MAX_REQUESTS; $n--;) {
            $request->data = $n;
            $streams[$client->send($request)] = $n;
        }
        for ($n = MAX_REQUESTS; $n--;) {
            /** @var $response Response */
            $response = $client->recv();
            Assert::same($streams[$response->streamId], (int)$response->data);
        }
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true
    ]);
    $http->on('request', function (\Swoole\Http\Request $request, \Swoole\Http\Response $response) {
        Coroutine::sleep(mt_rand(1, MAX_REQUESTS) / 1000);
        $response->end($request->rawContent());
    });
    $http->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
DONE
