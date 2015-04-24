<?php
$http = new swoole_http_server("127.0.0.1", 9501);

$http->set([
    'worker_num' => 8,
    'dispatch_mode' => 3,
    //'open_tcp_nodelay' => true,
]);

$http->on('request', function ($request, swoole_http_response $response) {
    $response->end("<h1>Hello Swoole.</h1>");
});

$http->start();
