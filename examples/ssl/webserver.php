<?php
$serv = new swoole_http_server("0.0.0.0", 9502, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
$serv->set([
    'ssl_cert_file' => __DIR__ . '/corpssl.crt',
    'ssl_key_file' => __DIR__ . '/corpssl.key',
    'ssl_client_cert_file' => __DIR__ . '/ca.crt',
    'ssl_verify_depth' => 10,
]);

$serv->on('Request', function(swoole_http_request $request, swoole_http_response $response) {
    //var_dump($request->get);
    //var_dump($request->post);
    //var_dump($request->cookie);
    //var_dump($request->files);
    var_dump($request->header);
    var_dump($request->server);
    global $serv;
    $info=  $serv->getClientInfo($request->fd);
    var_dump($info);
    $response->cookie("User", "Swoole");
    $response->header("X-Server", "Swoole");
    $response->end("<h1>Hello Swoole!</h1>");
});

$serv->start();
