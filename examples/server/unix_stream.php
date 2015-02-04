<?php
$serv = new swoole_server(__DIR__."/svr.sock", 0, SWOOLE_PROCESS, SWOOLE_UNIX_STREAM);
$serv->set(array(
    'worker_num' => 1,
));
$serv->on('connect', function ($serv, $fd, $from_id){
    echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});
$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
    $serv->send($fd, json_encode(array("hello" => '1213', "bat" => "ab")));
    //$serv->close($fd);
});
$serv->on('close', function ($serv, $fd, $from_id) {
    echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});
$serv->start();