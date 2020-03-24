<?php

require __DIR__ . '/functions.php';

use Swoole\Server;

//$serv = new Server("0.0.0.0", 9502, SWOOLE_BASE);
$serv = new Server("0.0.0.0", 9502);
$serv->set(
    array(
        'worker_num' => 4,
        'dispatch_mode' => 7,
        'open_length_check' => true,
        "package_length_type" => 'N',
        'package_body_offset' => 4,
        'enable_reuse_port' => true,
    )
);
$serv->on(
    'workerstart',
    function ($server, $id) {
        global $argv;
        swoole_set_process_name("php {$argv[0]}: worker");
    }
);

$serv->on(
    'connect',
    function (Server $serv, $fd, $tid) {
        //echo "connect\n";;
    }
);

$serv->on(
    'receive',
    function (Server $serv, $fd, $tid, $data) {
        $serv->send($fd, $data);
        //$serv->close($fd);
    }
);

$serv->on(
    'close',
    function (Server $serv, $fd, $tid) {
        //var_dump($serv->connection_info($fd));
        //echo "onClose\n";
    }
);

$serv->start();
