<?php
/**
 * User: lufei
 * Date: 2020/8/6
 * Email: lufei@swoole.com
 */

Co\run(function () {
    $server = new Co\Http\Server("127.0.0.1", 9502, false);
    $server->handle('/', function ($request, $response) {
        $response->end("<h1>Index</h1>");
    });
    $server->handle('/test', function ($request, $response) {
        $response->end("<h1>Test</h1>");
    });
    $server->handle('/stop', function ($request, $response) use ($server) {
        $response->end("<h1>Stop</h1>");
        $server->shutdown();
    });
    $server->start();
});
