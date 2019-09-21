--TEST--
swoole_http_server: dispatch_mode=7
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        Assert::eq($data, "hello");
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server("0.0.0.0", $pm->getFreePort());

    $http->set([
        'reactor_num' => 2,
        'worker_num' => 2,
        'dispatch_mode' => 7,
        'reload_async' => true,
        'log_level' => SWOOLE_LOG_WARNING
    ]);

    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $http->on('request', function ($request, Swoole\Http\Response $response) use ($http) {
        $response->write("hello");
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
