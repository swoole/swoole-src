<?php

use Swoole\Coroutine\Http\Client;

Co\run(function () {
    $host = 'www.swoole.com';
    $cli = new Client($host, 443, true);
    $cli->set(['timeout' => -1]);
    $cli->setHeaders([
        'Host' => $host,
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => '*',
        'Accept-Encoding' => 'gzip'
    ]);
    $cli->download('/dist/skin1/images/logo-white.png', '/tmp/logo.png');
});
