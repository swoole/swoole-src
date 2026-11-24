<?php
// A minimal HTTPS server with HTTP/2 enabled. Certificates are shared with
// the test suite. Run: php examples/http2/server_basic.php
require __DIR__ . '/../ssl/certs.php';

$server = new Swoole\Http\Server('127.0.0.1', 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$server->set([
    'ssl_cert_file' => SSL_CERT_DIR . 'server.crt',
    'ssl_key_file' => SSL_CERT_DIR . 'server.key',
    'open_http2_protocol' => true,
]);
$server->on('request', function ($request, $response) {
    $response->end('Hello over HTTP/2');
});
$server->start();
