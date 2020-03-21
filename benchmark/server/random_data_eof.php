<?php

use Swoole\Server;

define('N', 32 * 1024 * 1024);
define('R_DATA', base64_encode(random_bytes(N)));

//$serv = new swoole_server("0.0.0.0", 9502, SWOOLE_BASE);
$serv = new Server("0.0.0.0", 9502);

$serv->set(
    array(
        'open_eof_check' => true,
        'package_eof' => "\r\n",
        'enable_reuse_port' => true,
    )
);

$serv->on('workerstart', function ($server, $id) {
    global $argv;
    swoole_set_process_name("php {$argv[0]}: worker");
});

$serv->on('connect', function (Server $serv, $fd, $rid) {
    //echo "connect\n";;
});

$serv->on('receive', function (Server $serv, $fd, $rid, $data) {
    $hash = substr($data, 0, 32);
    if ($hash !== md5(substr($data, -130, 128))) {
        echo "Client Request Data Error\n";
        $serv->close($fd);
    } else {
        $len = mt_rand(1024, 1024 * 1024);
        $send_data = substr(R_DATA, rand(0, N - $len), $len);
        $serv->send($fd, md5(substr($send_data, -128, 128)) . $send_data."\r\n");
    }
});

$serv->on('close', function (Server $serv, $fd, $from_id) {
});

$serv->start();
