--TEST--
swoole_http_server: static file handler path overflow
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $cli = new \Co\Client(SWOOLE_TCP);
    $ret = $cli->connect('127.0.0.1', $pm->getFreePort());
    assert($ret);

    $ret = $cli->send("GET /" . str_repeat('a', 8192) . " HTTP/1.1\r\n\r\n");
    assert($ret);

    $ret = $cli->recv();
    assert(strpos($ret, 'swoole_test') !== false);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => dirname(dirname(__DIR__)) . '/examples/php',
    ]);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end('swoole_test');
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
