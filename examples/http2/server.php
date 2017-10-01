<?php
$key_dir = dirname(__DIR__) . '/ssl';
//$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE);
$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$http->set([
    'open_http2_protocol' => 1,
    'ssl_cert_file' => $key_dir.'/ssl.crt',
    'ssl_key_file' => $key_dir.'/ssl.key',
]);

$http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
    $response->end("<h1>Hello Swoole.</h1>");
});

$http->start();
