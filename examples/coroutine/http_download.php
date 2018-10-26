<?php
go(function () {
    $host = 'www.swoole.com';
    $cli = new \Swoole\Coroutine\Http\Client($host, 443, true);
    $cli->set(['timeout' => -1]);
    $cli->setHeaders([
        'Host' => $host,
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => '*',
        'Accept-Encoding' => 'gzip'
    ]);
    $cli->download('/static/files/swoole-logo.svg', __DIR__ . '/logo.svg');
});
