<?php
require __DIR__.'/functions.php';

$serv = new Swoole\Server("0.0.0.0", 9502, SWOOLE_BASE, SWOOLE_SOCK_UDP | SWOOLE_SSL);
$ssl_dir = dirname(__DIR__) . '/../examples/ssl';
$serv->set(
    array(
        //'worker_num' => 2,
        'ssl_cert_file' => $ssl_dir . '/ssl.crt',
        'ssl_key_file' => $ssl_dir . '/ssl.key',
    )
);

$serv->on(
    'connect',
    function (Swoole\Server $serv, $fd, $tid) {
        //echo "connect\n";
    }
);

$serv->on(
    'receive',
    function (Swoole\Server $serv, $fd, $tid, $data) {
        $serv->send($fd, SwooleBench\get_response($data));
        //$serv->close($fd);
    }
);

$serv->on(
    'close',
    function (Swoole\Server $serv, $fd, $tid) {
        //var_dump($serv->connection_info($fd));
        //echo "onClose\n";
    }
);

$serv->start();
