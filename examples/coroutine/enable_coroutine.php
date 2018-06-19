<?php

use Swoole\Http\Request;
use Swoole\Http\Response;

$http = new swoole_http_server("127.0.0.1", 8888);

$http->set([
    'enable_coroutine' => false // close build-in coroutine
]);

$http->on("request", function (Request $request, Response $response) {
    if ($request->server['request_uri'] == '/co') {
        go(function () use ($response) {
            $response->header("Content-Type", "text/plain");
            $response->end("Hello Coroutine#" . Co::getuid());
        });
    } else {
        $response->header("Content-Type", "text/plain");
        $response->end("Hello Swoole\n");
    }
});

$http->start();