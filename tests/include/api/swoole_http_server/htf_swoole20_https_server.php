<?php
$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$http->set([
    'ssl_cert_file' => __DIR__ . '/localhost-ssl/swoole_server.crt',
    'ssl_key_file' => __DIR__ . '/localhost-ssl/swoole_server.key',
]);
$http->on('request', function ($request, $response) {
    $response->header("Content-Type", "text/html; charset=utf-8");
    $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
});
$http->start();