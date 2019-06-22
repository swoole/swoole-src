--TEST--
swoole_http_server_coro: handle
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/") . PHP_EOL;
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/test/index/") . PHP_EOL;
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/stop?hello=1") . PHP_EOL;
    });
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->end("<h1>Index</h1>");
        });
        $server->handle('/test', function ($request, $response) {
            $response->end("<h1>Test</h1>");
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
<h1>Index</h1>
<h1>Test</h1>
<h1>Stop</h1>
