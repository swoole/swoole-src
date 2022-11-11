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
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/") . PHP_EOL;
            
        go(function () use ($pm) {
            echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/sleep") . PHP_EOL;
        });

        go(function () use ($pm) {
            echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/shutdown") . PHP_EOL;
            try {
                echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/") . PHP_EOL;
            } catch(Throwable $e) {
                Assert::contains($e->getMessage(), 'Connection reset by peer');
                echo "done\n";
            }
        });
    });
};
$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function ($request, $response) {
            $response->end("index");
        });
        $server->handle('/sleep', function ($request, $response) {
            Co::sleep(0.2);
            $response->end("sleep");
        });
        $server->handle('/shutdown', function ($request, $response) use ($server) {
            $response->end("shutdown");
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
index
shutdown
sleep
done