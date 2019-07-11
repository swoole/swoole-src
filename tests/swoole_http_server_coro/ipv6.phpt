--TEST--
swoole_http_server_coro: ipv6
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ipv6();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;

\Swoole\Runtime::enableCoroutine();
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        echo file_get_contents("http://[::1]:{$pm->getFreePort()}/") . PHP_EOL;
        echo file_get_contents("http://[::1]:{$pm->getFreePort()}/stop?hello=1") . PHP_EOL;
    });
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("::1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->end("<h1>Index</h1>");
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
<h1>Stop</h1>
