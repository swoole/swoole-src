<?php
$server = new Swoole\Http\Server("0.0.0.0", 9501, SWOOLE_BASE);

$server->on('Request', function ($req, $resp) {
    $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', 80);
    $cli->setHeaders([
        'Host' => "localhost",
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $cli->set([ 'timeout' => 1]);
    $cli->get('/');
    $cli->close();
    $resp->end($cli->body);
});

$server->start();
