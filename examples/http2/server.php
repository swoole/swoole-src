<?php
Co::set([
    'trace_flags' => SWOOLE_TRACE_HTTP2,
    'log_level' => 0,
]);
$key_dir = dirname(dirname(__DIR__)) . '/tests/include/api/swoole_http_server/localhost-ssl';
$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$http->set([
    'open_http2_protocol' => 1,
    'enable_static_handler' => TRUE,
    'document_root' => dirname(__DIR__),
    'ssl_cert_file' => $key_dir . '/server.crt',
    'ssl_key_file' => $key_dir . '/server.key',
]);

$http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
    $response->end("<h1>Hello Swoole.</h1>");
});

$http->start();
