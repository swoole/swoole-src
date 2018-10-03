<?php
$serv = new swoole_server("0.0.0.0", 9501);
//$serv->on('connect', function ($serv, $fd, $reactor_id){
//	echo "[#".posix_getpid()."]\tClient@[$fd:$reactor_id]: Connect.\n";
//});
$serv->set(array(
    'worker_num' => 1,
));

$serv->on('receive', function (swoole_server $serv, $fd, $reactor_id, $data) {
    usleep(rand(100000, 2000000));
    var_dump(round($serv->getReceivedTime(), 10));
});

//$serv->on('close', function ($serv, $fd, $reactor_id) {
//	echo "[#".posix_getpid()."]\tClient@[$fd:$reactor_id]: Close.\n";
//});

$serv->start();
