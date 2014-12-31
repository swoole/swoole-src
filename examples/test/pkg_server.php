<?php
class PkgServer
{
    function onReceive($serv, $fd, $from_id, $data)
    {
        $header = unpack('nlen/Nindex/Nsid', substr($data, 0, 10));
        if ($header['index'] % 1000 == 1) {
            echo "recv package. sid={$header['sid']}, length=" . strlen($data) . "\n";
        }
    }

    function onConnect($serv, $fd, $from_id)
    {

    }

    function onClose($serv, $fd, $from_id)
    {

    }
}

$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(
    [
        'worker_num'            => 4,
        'open_length_check'     => true,
        'package_max_length'    => 81920,
        'package_length_type'   => 'n', //see php pack()
        'package_length_offset' => 0,
        'package_body_offset'   => 2,
        'task_worker_num'       => 0
    ]
);

$cb = new PkgServer();
$serv->on('Connect', [$cb, 'onConnect']);
$serv->on('receive', [$cb, 'onReceive']);
$serv->on('Close', [$cb, 'onClose']);
$serv->start();
