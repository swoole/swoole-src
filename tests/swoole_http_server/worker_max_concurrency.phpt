--TEST--
swoole_http_server: worker_max_concurrency
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
        $url = 'http://127.0.0.1:' . $pm->getFreePort(0) . '/';
        $n = SERVER_WORKER_MAX_CONCURRENCY * 3;
        $cid_list = [];
        while ($n--) {
            $cid_list[] = go(function () use ($url) {
                $c = Swoole\Coroutine\Http\get($url);
                Assert::eq($c->getStatusCode(), 200);
                Assert::eq($c->getBody(), GREETING_MESSAGE);
            });
        }

        // wait
        Coroutine::join($cid_list);
        $c = Swoole\Coroutine\Http\get($url.'stats');
        Assert::eq($c->getStatusCode(), 200);
        $json = json_decode($c->getBody());
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
