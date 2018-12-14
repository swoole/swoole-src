<?php
use Swoole\Coroutine as co;
co::create(function () {
    $cli = new co\http\client('127.0.0.1', 9501);
    $cli->setHeaders(['Host' => 'localhost']);
    $cli->set(['http_proxy_host' => HTTP_PROXY_HOST, 'http_proxy_port' => HTTP_PROXY_PORT]);
    $result = $cli->get('/get?json=true');
    var_dump($cli->body);
//     assert($result);
//     $ret = json_decode($cli->body, true);
//     assert(is_array($ret) and $ret['json'] == 'true');
});
