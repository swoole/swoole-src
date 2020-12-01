--TEST--
swoole_http_server: duplicate header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:{$pm->getFreePort()}/");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, TRUE);
    echo curl_exec($ch);
    curl_close($ch);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'enable_coroutine' => false,
        'log_file' => '/dev/null'
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->header("Test-Value: a\r\n");
        $response->header("teST-valUe : b1234\r\n");
        $response->header("test-VALUE: c\r\n", null, false);
        $response->header("test-VALUE: d5678");
        $response->header("content-length: 10000\n ");
        $response->end("hello world");
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
HTTP/1.1 200 OK
Test-Value: a
Test-Value : b1234
test-VALUE: c
Test-Value: d5678
Content-Length: 10000
Server: swoole-http-server
Connection: keep-alive
Content-Type: text/html
Date: %s
Content-Length: 11

hello world