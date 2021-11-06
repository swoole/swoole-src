--TEST--
swoole_http2_server: worker_max_concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use Swoole\Coroutine;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

const SERVER_WORKER_MAX_CONCURRENCY = 4;
const GREETING_MESSAGE = 'hello world';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        $n = SERVER_WORKER_MAX_CONCURRENCY * 3;
        $cid_list = [];
        while ($n--) {
            $cid_list[] = go(function () use ($pm) {
                $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
                Assert::true($cli->connect());
                Assert::greaterThan($streamId = $cli->send(new Swoole\Http2\Request), 0);
                $response = $cli->recv();
                Assert::eq($response->statusCode, 200);
                Assert::eq($response->data, GREETING_MESSAGE);
            });
        }

        // wait
        Coroutine::join($cid_list);

        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($cli->connect());
        $req = new Swoole\Http2\Request;
        $req->path = '/stats';
        Assert::greaterThan($streamId = $cli->send($req), 0);
        $response = $cli->recv();
        Assert::eq($response->statusCode, 200);
        $json = json_decode($response->data);
        Assert::true(isset($json->coroutine_peek_num));
        Assert::eq($json->coroutine_peek_num, SERVER_WORKER_MAX_CONCURRENCY);

        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
//    $mode = SWOOLE_BASE;
    $mode = SERVER_MODE_RANDOM;
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
    $http->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'worker_max_concurrency' => SERVER_WORKER_MAX_CONCURRENCY,
    ]);
    $http->on('start', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm, $http) {
        if ($request->server['request_uri'] == '/stats') {
            $response->end(json_encode($http->stats()));
            return;
        }
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
