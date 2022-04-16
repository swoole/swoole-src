--TEST--
swoole_http2_server: max_concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Coroutine;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

const SERVER_MAX_CONCURRENCY = 4;
const GREETING_MESSAGE = 'hello world';

$pm = new ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {

        $n = SERVER_MAX_CONCURRENCY;
        // 200
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

        System::sleep(0.005);

        // 403, high concurrency
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

        // wait
        Coroutine::join($cid_list);

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
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'log_file' => '/dev/null',
        'max_concurrency' => SERVER_MAX_CONCURRENCY,
        'open_http2_protocol' => true,
    ]);
    $http->on('start', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        System::sleep(0.1);
        $response->end(GREETING_MESSAGE);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
