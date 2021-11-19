<?php
$http = new Swoole\Http\Server("127.0.0.1", 9501, SWOOLE_BASE);
$http->set(array(
    'log_file' => '/dev/null'
));
use Swoole\Coroutine as co;
// $http->on("WorkerStart", function (\Swoole\Server $serv)
// {
//
// });
$http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response)
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
