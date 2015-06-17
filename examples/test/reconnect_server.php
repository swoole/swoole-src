<?php
class ReconnectServer
{
    private $count = array();

    function onReceive(swoole_server $serv, $fd, $from_id, $data)
    {
        $this->count[$fd]++;
        echo "Client#$fd recv: $data\n";

        if ($this->count[$fd] > 10)
        {
            $serv->close($fd);
        }
        else
        {
            $serv->send($fd, "hello client");
        }
    }

    function onConnect($serv, $fd, $from_id)
    {
        echo "Client#$fd connected\n";
        $this->count[$fd] = 0;
    }

    function onClose($serv, $fd, $from_id)
    {
        unset($this->count[$fd]);
        echo "Client#$fd closed\n";
    }
}

$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(
    [
        'worker_num'            => 1,
    ]
);

$cb = new ReconnectServer();
$serv->on('Connect', [$cb, 'onConnect']);
$serv->on('receive', [$cb, 'onReceive']);
$serv->on('Close', [$cb, 'onClose']);
$serv->start();
