<?php
$serv = new Swoole\Server("0.0.0.0", 9502, SWOOLE_BASE);
//$serv = new swoole_server("0.0.0.0", 9502);
$serv->set(
    array(
        'worker_num' => 2,
        'enable_reuse_port' => true,
    )
);
$serv->on('workerstart', function ($server, $id) {
    global $argv;
    swoole_set_process_name("php {$argv[0]}: worker");
});

$serv->on('connect', function (Swoole\Server $serv, $fd, $from_id) {
    //echo "connect\n";;
});

$serv->on('receive', function (Swoole\Server $serv, $fd, $from_id, $data) {
    $serv->send($fd, "Swoole: " . $data);
    //$serv->close($fd);
});

$serv->on('close', function (Swoole\Server $serv, $fd, $from_id) {
    //var_dump($serv->connection_info($fd));
    //echo "onClose\n";
});

$serv->start();
