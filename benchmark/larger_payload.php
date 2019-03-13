<?php
define('PORT', 9501);

$http = new swoole_http_server('127.0.0.1', PORT, SWOOLE_BASE);

$http->set(['worker_num' => 1, 'enable_coroutine' => false, ]);

$http->on('start', function ($server) {
    echo 'Swoole http server is started at 127.0.0.1 on port ' . PORT;
});

$http->on('request', function ($request, $response) {
    $response->header('Content-Type', 'text/plain');
    $response->end(str_repeat('A', 1 * 1024 * 1024));
});

$http->start();
