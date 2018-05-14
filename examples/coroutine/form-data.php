<?php
go(function () {
    $cli = new Swoole\Coroutine\Http\Client('eu.httpbin.org', 80);
    $cli->setHeaders([
        'Host' => "eu.httpbin.org",
        'Content-Type' => 'multipart/form-data' // Swoole will add random boundary automatically
    ]);
    $cli->set(['timeout' => -1]);
    $cli->post('/post', ['foo' => 'bar']);
    var_dump(json_decode($cli->body, true));
    $cli->close();
});