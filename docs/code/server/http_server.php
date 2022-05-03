<?php
/**
 * User: lufei
 * Date: 2020/8/4
 * Email: lufei@swoole.com
 */

$http = new Swoole\Http\Server('0.0.0.0', 9501);

$http->on('request', function ($request, $response) {
    var_dump($request);
    $response->header("Content-Type", "text/html; charset=utf-8");
    $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
});

$http->start();
