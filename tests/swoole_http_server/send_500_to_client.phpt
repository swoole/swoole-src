--TEST--
swoole_http_server: When the process restarts, send a 500 status code to the clients waiting in the queue
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Coroutine\WaitGroup;
use Swoole\Runtime;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine\Http\Client;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Runtime::setHookFlags(SWOOLE_HOOK_ALL);
    $statusCodes = [];
    run(function () use ($pm, &$statusCodes) {
        $waitGroup = new WaitGroup();
        $index = 0;
        go(function () use ($waitGroup, $pm, &$index, &$statusCodes) {
            $waitGroup->add();
            $client = new Client('127.0.0.1', $pm->getFreePort());
            $client->set(['timeout' => 15]);
            $client->get('/?id=' . $index++);
            if (!isset($statusCodes[$client->statusCode])) {
                $statusCodes[$client->statusCode] = 0;
            }
            $statusCodes[$client->statusCode]++;
            $waitGroup->done();
        });

        sleep(1);

        for ($i = 0; $i < 10; $i++) {
            go(function () use ($waitGroup, $pm, &$index, &$statusCodes) {
                $waitGroup->add();
                $client = new Client('127.0.0.1', $pm->getFreePort());
                $client->set(['timeout' => 15]);
                $client->get('/?id=' . $index++);
                if (!isset($statusCodes[$client->statusCode])) {
                    $statusCodes[$client->statusCode] = 0;
                }
                $statusCodes[$client->statusCode]++;
                $waitGroup->done();
            });
        }

        $waitGroup->wait();
        $pm->kill();
    });
    Assert::greaterThanEq($statusCodes[503], 8);
    Assert::lessThanEq($statusCodes[200], 3);
    echo 'DONE';
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'enable_coroutine' => true,
        'worker_max_concurrency' => 1,
        'max_wait_time' => 10,
        'reload_async' => true,
        'hook_flags' => SWOOLE_HOOK_ALL,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($http) {
        $http->reload();
        sleep(2);
        $response->end("id=" . $request->get['id']);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
