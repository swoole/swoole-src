--TEST--
swoole_http2_server: max_concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine\System;
use Swoole\Coroutine;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

const SERVER_MAX_CONCURRENCY = 4;
const GREETING_MESSAGE = 'hello world';

$started = new Atomic();
$release = new Atomic();
$pm = new ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function ($pid) use ($pm, $started, $release) {
    run(function () use ($pm, $started, $release) {

        $n = SERVER_MAX_CONCURRENCY;
        // 200, low concurrency
        $cid_list = [];
        while ($n--) {
            $cid_list[] = go(function () use ($pm) {
                $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
                $cli->set(['timeout' => 10]);
                Assert::true($cli->connect());
                Assert::greaterThan($streamId = $cli->send(new Swoole\Http2\Request), 0);
                $response = $cli->recv();
                Assert::eq($response->statusCode, 200);
                Assert::eq($response->data, GREETING_MESSAGE);
            });
        }

        // Wait for admission, not a fixed delay: later requests must not overtake this batch.
        $accepted = $cid_list;
        $deadline = microtime(true) + 5;
        while ($started->get() < SERVER_MAX_CONCURRENCY && microtime(true) < $deadline) {
            System::sleep(0.001);
        }
        Assert::same($started->get(), SERVER_MAX_CONCURRENCY);

        // 503, high concurrency. Keep the accepted requests active until every rejection arrives.
        $cid_list = [];
        $n = SERVER_MAX_CONCURRENCY;
        while ($n--) {
            $cid_list[] = go(function () use ($pm) {
                $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
                $cli->set(['timeout' => 10]);
                Assert::true($cli->connect());
                Assert::greaterThan($streamId = $cli->send(new Swoole\Http2\Request), 0);
                $response = $cli->recv();
                Assert::eq($response->statusCode, 503);
            });
        }

        Coroutine::join($cid_list);
        Assert::same($started->get(), SERVER_MAX_CONCURRENCY);
        $release->set(1);
        Coroutine::join($accepted);

        // low concurrency
        $n = SERVER_MAX_CONCURRENCY;
        $cid_list = [];
        while ($n--) {
            $cid_list[] = go(function () use ($pm) {
                $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
                $cli->set(['timeout' => 10]);
                Assert::true($cli->connect());
                Assert::greaterThan($streamId = $cli->send(new Swoole\Http2\Request), 0);
                $response = $cli->recv();
                Assert::eq($response->statusCode, 200);
                Assert::eq($response->data, GREETING_MESSAGE);
            });
        }

        Coroutine::join($cid_list);
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm, $started, $release) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'log_file' => '/dev/null',
        'worker_num' => 2,
        'max_concurrency' => SERVER_MAX_CONCURRENCY,
        'open_http2_protocol' => true,
    ]);
    $http->on('start', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($started, $release) {
        $started->add();
        while (!$release->get()) {
            System::sleep(0.001);
        }
        $response->end(GREETING_MESSAGE);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
