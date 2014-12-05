<?php
$http = new swoole_http_server("127.0.0.1", 9501);
$http->on('request', function ($request, swoole_http_response $response) {
    $response->end("<h1>Hello Swoole.</h1>");
});
$http->start();
