<?php
$serv = new swoole_server("::1", 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP6);
$serv->set(array(
    'worker_num' => 1,
));
$serv->on('connect', function ($serv, $fd, $from_id){
    echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});
$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
    var_dump($serv->connection_info($fd));
	$serv->send($fd, json_encode(array("hello" => '1213', "bat" => "ab")));
    //$serv->close($fd);
});
$serv->on('close', function ($serv, $fd, $from_id) {
    echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});
$serv->start();
