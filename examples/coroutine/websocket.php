<?php
$ws = new swoole_websocket_server("127.0.0.1", 9501, SWOOLE_BASE);
$ws->set(array(
    'log_file' => '/dev/null'
));
$ws->on("WorkerStart", function (\swoole_server $serv) {

});

$ws->on('open', function ($serv, swoole_http_request $request) {
    //$ip = co::gethostbyname('www.baidu.com');
    if (1) {
        $serv->push($request->fd, "start\n");
    }
});

$ws->on('message', function ($serv, $frame) {
    var_dump($frame);
    co::sleep(0.1);
    $data = $frame->data;
    $serv->push($frame->fd, "hello client {$data}\n");
});

$ws->start();
