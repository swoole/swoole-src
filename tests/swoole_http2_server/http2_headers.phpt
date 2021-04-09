--TEST--
swoole_http2_server: array headers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $output = `curl --http2-prior-knowledge --silent -I http://127.0.0.1:{$pm->getFreePort()}`;
    echo $output;
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->header('test-value', [
            "a\r\n",
            'd5678',
            "e  \n ",
            null,
            5678,
            3.1415926,
        ]);
        $response->end("<h1>Hello Swoole.</h1>");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
HTTP/2 200 
test-value: a
test-value: d5678
test-value: e
test-value: 5678
test-value: 3.1415926
server: swoole-http-server
date: %s
content-type: text/html
content-length: 22
