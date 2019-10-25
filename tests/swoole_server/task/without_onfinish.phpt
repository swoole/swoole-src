--TEST--
swoole_server/task: task & finish
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    for ($i = MAX_CONCURRENCY_LOW; $i--;) {
        go(function () use ($pm) {
            $ret = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}");
            Assert::same($ret, 'Hello Swoole!');
        });
    }
    swoole_event_wait();
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set([
        'log_file' => '/dev/null',
        'task_worker_num' => 4
    ]);
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($http) {
        Assert::assert($response->detach());
        $http->task($response->fd);
    });
    $http->on('task', function ($a, $b, $c, string $fd) {
        $response = swoole_http_response::create($fd);
        $response->end('Hello Swoole!');
        return null; // no on finish?
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
