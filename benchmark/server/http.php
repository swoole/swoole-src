<?php
require __DIR__.'/functions.php';
use Swoole\Http\Server;
use Swoole\Http\Response;
use Swoole\Http\Request;

$http = new Server("127.0.0.1", 9501);
///$http = new Server("127.0.0.1", 9501, SWOOLE_BASE);

$pool = [];

$http->set([
//    'worker_num' => 4,
    'hook_flags' => SWOOLE_HOOK_ALL,
               'enable_reuse_port' => true,
]);

$http->on('request', function (Request $request, Response $response) use (&$pool) {
//    var_dump($request->server['request_uri']);
    if ($request->server['request_uri'] == '/') {
        $response->header('Last-Modified', 'Thu, 18 Jun 2015 10:24:27 GMT');
        $response->header('E-Tag', '55829c5b-17');
        $response->header('Accept-Ranges', 'bytes');
        $response->end("<h1>\nHello Swoole.\n</h1>");
    } elseif ($request->server['request_uri'] == '/redis') {
        $redis = new redis;
        $redis->connect('127.0.0.1', 6379);
        $value = $redis->get('key');
        $redis->close();
        $pool[] = $redis;
        $response->end("<h1>Value=" . $value . "</h1>");
    } elseif ($request->server['request_uri'] == '/redis') {
        $response->end("<pre>" . var_export($pool, 1) . "</pre>\n");
    }
});

$http->start();
