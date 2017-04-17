<?php
$ssl_dir = realpath('../../tests/ssl');
$serv = new swoole_websocket_server("0.0.0.0", 9502, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
//$serv = new swoole_websocket_server("0.0.0.0", 9502, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$serv->set([
    'ssl_cert_file' => $ssl_dir . '/ssl.crt',
    'ssl_key_file' => $ssl_dir . '/ssl.key',
    'worker_num' => 1,
]);

$port = $serv->listen('127.0.0.1', 9501, SWOOLE_SOCK_TCP);
$port->on('receive', function($serv, $fd, $reactor_id, $data){
    var_dump($fd, $reactor_id, $data);
    $serv->send($fd, "Swoole: $data");
});

$serv->on('connect', function ($_server, $fd) {
    echo "client {$fd} connect\n";
});

$serv->on('open', function (swoole_websocket_server $_server, swoole_http_request $request) {
    echo "server#{$_server->worker_pid}: handshake success with fd#{$request->fd}\n";
//    var_dump($request);
});

$serv->on('request', function ($req, $resp) {
    $resp->end(file_get_contents(__DIR__.'/websocket_client.html'));
});

$serv->on('message', function (swoole_websocket_server $_server, $frame) {
    var_dump($frame->data);
    echo "received ".strlen($frame->data)." bytes\n";
    $_send = str_repeat('B', rand(100, 800));
    $_server->push($frame->fd, $_send);
    // echo "#$i\tserver sent " . strlen($_send) . " byte \n";
});

$serv->on('close', function ($_server, $fd) {
    echo "client {$fd} closed\n";
});

$serv->start();
