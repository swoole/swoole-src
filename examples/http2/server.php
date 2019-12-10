<?php
Co::set([
    'trace_flags' => SWOOLE_TRACE_HTTP2,
    'log_level' => 0,
]);
$http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE);
$http->set([
    'open_http2_protocol' => 1,
    'enable_static_handler'         => TRUE,
    'document_root'                 => __DIR__,
]);

$http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
    $response->end("<h1>Hello Swoole.</h1>");
});

$http->start();
