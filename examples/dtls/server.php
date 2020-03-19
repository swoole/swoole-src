<?php
$server = new swoole_server('0.0.0.0', 9905, SWOOLE_BASE, SWOOLE_SOCK_UDP | SWOOLE_SSL);

$server->set(
    [
        'ssl_cert_file' => __DIR__ . '/../ssl/ssl.crt',
        'ssl_key_file' => __DIR__ . '/../ssl/ssl.key',
        //'ssl_method' => SWOOLE_TLSv1_2_SERVER_METHOD,
        'worker_num' => 1,
        //'ssl_client_cert_file' => __DIR__ . '/ca.crt',
        //'ssl_verify_depth' => 10,
    ]
);

$server->on('Receive', function (swoole_server $serv, $fd, $tid, $data)
{
    var_dump($fd, $data, $serv->getClientInfo($fd));
    $serv->send($fd, "Swoole: $data\n");
    //echo "close dtls session\n";
    //$serv->close($fd);
});

$server->start();
