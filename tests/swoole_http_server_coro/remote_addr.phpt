--TEST--
swoole_http_server_coro: remote_addr
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;

use Swoole\Http\Request;

$pm->parentFunc = function () use ($pm) {
    go(
        function () use ($pm) {
            $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            Assert::assert($client->get('/'));
            $data = $client->getBody();
            Assert::assert($data);
            $json = json_decode($data);
            $info = $client->getsockname();
            Assert::eq($json->remote_addr, $info['address']);
            Assert::eq($json->remote_port, $info['port']);
            httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/stop") . PHP_EOL;
        }
    );
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function (Request $request, $response) {
            $response->end(json_encode($request->server));
        });
        $server->handle('/stop', function ($request, $response) use ($server) {
            $response->end("<h1>Stop</h1>");
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
    swoole_event_wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
