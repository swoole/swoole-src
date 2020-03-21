<?php
require __DIR__.'/functions.php';
swoole_async_set(array('enable_reuse_port' => true));
//$serv = new Swoole\Server("0.0.0.0", 9503, SWOOLE_BASE);
$serv = new swoole_server("0.0.0.0", 9502);
$serv->set(array(
    'worker_num' => 2,
));
$serv->on('workerstart', function ($server, $id) {
    global $argv;
    swoole_set_process_name("php {$argv[0]}: worker");
});

$serv->on('connect', function (Swoole\Server $serv, $fd, $tid) {
    echo "connect\n";
});

$serv->on('receive', function (Swoole\Server $serv, $fd, $tid, $data) {
    $serv->send($fd, SwooleBench\get_response($data));
    //$serv->close($fd);
});

$serv->on('close', function (Swoole\Server $serv, $fd, $tid) {
    //var_dump($serv->connection_info($fd));
    //echo "onClose\n";
});

$serv->start();
