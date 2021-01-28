--TEST--
swoole_http_server: sendfile with dispatch_mode=7
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Server;

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $n = MAX_CONCURRENCY_LOW;
        while ($n--) {
            go(function () use ($pm) {
                $cli = new Client('127.0.0.1', $pm->getFreePort());
                $cli->setHeaders(['KeepAlive' => 'off', 'Connection' => 'close']);
                for ($i = MAX_REQUESTS_LOW; $i--;) {
                    $cli->get('/');
                    Assert::contains($cli->getBody(), 'swoole_http_server: sendfile with dispatch_mode=7');
                }
            });
        }
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('0.0.0.0', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $http->set([
        'log_file' => '/dev/null',
        'dispatch_mode' => 7,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->sendfile(__FILE__);
    });

    $http->on('message', function(){});
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
