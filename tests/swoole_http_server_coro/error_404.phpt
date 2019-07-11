--TEST--
swoole_http_server_coro: 404 error
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        Assert::assert(httpGetStatusCode("http://127.0.0.1:{$pm->getFreePort()}/test") == 404);
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/stop?hello=1") . PHP_EOL;
    });
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/hello', function ($request, $response) {
            $response->end("<h1>hello</h1>");
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
<h1>Stop</h1>
