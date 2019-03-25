--TEST--
swoole_http_server: raw-content
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$payload = str_repeat('A', rand(1024, 65536));
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        global $payload;
        $httpClient = new Co\http\Client(HTTP_SERVER_HOST, $pm->getFreePort(), false);
        $httpClient->setMethod("POST");
        $httpClient->setData($payload);
        $ok = $httpClient->execute("/rawcontent");
        assert($ok);
        Assert::eq($httpClient->statusCode, 200);
        Assert::eq($httpClient->errCode, 0);
        Assert::eq($httpClient->body, $payload);
        $pm->kill();
    });
    swoole_event_wait();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->end($request->rawcontent());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--