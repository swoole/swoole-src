<?php
$ser = new swoole_server("127.0.0.1", 5900, SWOOLE_BASE | SWOOLE_PACKET);
$ser->set(array("worker_num" => 1));

$ser->on('receive',
    function (swoole_server $ser, $fd, $from_id, $data)
    {
        echo "data :{$data},len:" . strlen($data) . "\n";
        $ser->send($fd, "12345");
    });

$ser->start();

