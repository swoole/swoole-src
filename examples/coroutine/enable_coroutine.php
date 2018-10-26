<?php

use Swoole\Http\Request;
use Swoole\Http\Response;

$http = new swoole_http_server('127.0.0.1', 9501);

$http->set([
    'enable_coroutine' => false, // close build-in coroutine
]);

$http->on('workerStart', function () {
    echo "Coroutine is " . (Co::getuid() > 0 ? 'enable' : 'disable')."\n";
});

$http->on("request", function (Request $request, Response $response) {
    $response->header("Content-Type", "text/plain");
    if ($request->server['request_uri'] == '/co') {
        go(function () use ($response) {
            $response->end("Hello Coroutine #" . Co::getuid());
        });
    } else {
        $response->end("Hello Swoole #" . Co::getuid());
    }
});

$http->start();
