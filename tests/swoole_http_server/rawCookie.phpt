--TEST--
swoole_http_server: raw-cookie
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$simple_http_server = __DIR__ . "/../include/api/swoole_http_server/simple_http_server.php";

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function() use ($pm) {
        $httpClient = new Co\http\Client(HTTP_SERVER_HOST, $pm->getFreePort(), false);
        $httpClient->setMethod("POST");
        $httpClient->setData("HELLO");
        $ok = $httpClient->execute("/rawcookie");
        Assert::assert($ok);
        Assert::same($httpClient->statusCode, 200);
        Assert::same($httpClient->errCode, 0);
        Assert::same($httpClient->body, "Hello World!");
        $pm->kill();
    });
    swoole_event_wait();
};
$pm->childFunc = function () use ($pm, $simple_http_server) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $name = "name";
        $value = "value";
        // $expire = $request->swoole_server["request_time"] + 3600;
        $expire = 0;
        $path = "/";
        $domain = "";
        $secure = false;
        $httpOnly = true;
        // string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, string $domain = "" [, bool $secure = false [, bool $httponly = false ]]]]]]
        $response->cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
        $expect = "name=value; path=/; httponly";
        Assert::assert(in_array($expect, $response->cookie, true));
        $response->cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
        $response->rawcookie("rawcontent", $request->rawcontent());
        $response->end("Hello World!");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
