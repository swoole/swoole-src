<?php
$http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
$http->set(array(
    'log_file' => '/dev/null'
));
use Swoole\Coroutine as co;
// $http->on("WorkerStart", function (\swoole_server $serv)
// {
//
// });
$http->on('request', function (swoole_http_request $request, swoole_http_response $response)
{
    $ch = new co\Channel(1);
    $out = new co\Channel(1);
    Swoole\Coroutine::create(function() use ($ch, $out) {
        $out->push("OK");
        $out->push("OK");
    });
    $ret = $out->pop();
    var_dump($ret);
    $ret = $out->pop();
    var_dump($ret);
    $response->end("$ret\n");
});
$http->start();
