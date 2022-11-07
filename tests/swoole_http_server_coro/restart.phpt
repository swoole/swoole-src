--TEST--
swoole_http_server_coro: graceful shutdown
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $n = 2;
        while ($n--) {
            echo "[$n]", httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/") . PHP_EOL;
            echo "[$n]", httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/shutdown") . PHP_EOL;
            usleep(150000);
        }
    });
};
$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->end("index");
        });
        $server->handle('/shutdown', function ($request, $response) use ($server) {
            $response->end("shutdown");
            $server->shutdown();
        });
        $pm->wakeup();

        $n = 2;
        while ($n--) {
            $server->start();
            usleep(100000);
        }
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
[1]index
[1]shutdown
[0]index
[0]shutdown