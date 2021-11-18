<?php
$ws = new Swoole\WebSocket\Server("127.0.0.1", 9501, SWOOLE_BASE);
$ws->set(array(
    'log_file' => '/dev/null'
));
$ws->on("WorkerStart", function (\Swoole\Server $serv) {

});

$ws->on('open', function ($serv, Swoole\Http\Request $request) {
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
