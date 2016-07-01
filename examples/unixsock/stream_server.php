<?php
$serv = new swoole_server(__DIR__."/svr.sock", 9501, SWOOLE_BASE, SWOOLE_SOCK_UNIX_STREAM);
$serv->set(array(
    //'tcp_defer_accept' => 5,
    'worker_num' => 1,
    //'daemonize' => true,
    //'log_file' => '/tmp/swoole.log'
));

$serv->on('start', function($serv){
   chmod($serv->host, 0777);
});

$serv->on('Connect', function($serv, $fd, $reactorId) {
   echo "Connect, client={$fd}\n";
});

$serv->on('Close', function($serv, $fd, $reactorId) {
    echo "Close, client={$fd}\n";
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data)
{
    echo "[#" . posix_getpid() . "]\tClient[$fd]: $data\n";
    $serv->send($fd, json_encode(array("hello" => $data, "from" => $from_id)) . PHP_EOL);
});

$serv->start();