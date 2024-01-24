<?php

$http = new Swoole\Http\Server("0.0.0.0", 9501);

$http->on('request', function ($req, Swoole\Http\Response $resp) use ($http) {
    if ($req->server['request_uri'] == '/') {
        $resp->header('Content-Encoding', '');
        $resp->end(str_repeat('A', 1024));
    } elseif ($req->server['request_uri'] == '/gzip') {
        $resp->end(str_repeat('A', 1024));
    } else {
        $resp->status(404);
        $resp->end();
    }
});

$http->start();
