--TEST--
swoole_http_server: Github#5146 HTTP服务器，添加响应cookie时，如果设置了过期时间会内存泄漏
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}");
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}");
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}");
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}");
        httpRequest("http://127.0.0.1:{$pm->getFreePort()}");
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($http) {
        $previous = memory_get_usage();
        $response->cookie(
            'test_cookie',
            'hello',
            time() + (24 * 60 * 60)
        );

        global $previous;
        global $item;
        $current = memory_get_usage();
        $stats = [
            'id' => $http->getWorkerId(),
            'item' => $item++,
            'prev_mem' => $previous,
            'curr_mem' => $current,
            'diff_mem' => $current - $previous,
        ];
        $previous = $current;

        echo json_encode($stats), PHP_EOL;
        $response->end('test response');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
{"id":%d,"item":null,"prev_mem":null,"curr_mem":%d,"diff_mem":%d}
{"id":%d,"item":%d,"prev_mem":%d,"curr_mem":%d,"diff_mem":%d}
{"id":%d,"item":%d,"prev_mem":%d,"curr_mem":%d,"diff_mem":0}
{"id":%d,"item":%d,"prev_mem":%d,"curr_mem":%d,"diff_mem":0}
{"id":%d,"item":%d,"prev_mem":%d,"curr_mem":%d,"diff_mem":0}
DONE
