<?php
$serv = new swoole_server(__DIR__."/svr.sock", 9501, SWOOLE_PROCESS, SWOOLE_UNIX_DGRAM);
$serv->set(array(
    //'tcp_defer_accept' => 5,
    'worker_num' => 1,
    //'daemonize' => true,
    //'log_file' => '/tmp/swoole.log'
));
//$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
//    echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
//    $serv->send($fd, json_encode(array("hello" => $data, "from" => $from_id)).PHP_EOL);
//});

$serv->on('Packet', function (swoole_server $serv, $data, $addr) {
    //echo "[#".posix_getpid()."]\tClient[{$addr['address']}]: $data\n";
    var_dump($addr);
    $serv->send($addr['address'], json_encode(array("hello" => $data, "addr" => $addr)).PHP_EOL);
});

$serv->start();