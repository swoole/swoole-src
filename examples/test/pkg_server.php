<?php

class PkgServer
{
    private $count = array();
    private $index = array();
    private $recv_bytes = 0;

    private $show_lost_package = false;

    function onWorkerStart($serv, $id)
    {
        sleep(1);
    }

    function onReceive($serv, $fd, $from_id, $data)
    {
        $header = unpack('nlen/Nindex/Nsid', substr($data, 0, 10));
        if ($header['index'] % 1000 == 0)
        {
            echo "#{$header['index']} recv package. sid={$header['sid']}, length=" . strlen($data) . "\n";
        }
        $this->count++;
        if ($header['index'] > PKG_NUM)
        {
            echo "invalid index #{$header['index']}\n";
        }
        $this->recv_bytes += strlen($data);
        $this->index[$header['index']] = true;
    }

    function onConnect($serv, $fd, $from_id)
    {
        $this->count = 0;
    }

    function onClose($serv, $fd, $from_id)
    {
        echo "Total count={$this->count}, bytes={$this->recv_bytes}\n";

        if ($this->show_lost_package)
        {
            for ($i = 0; $i < PKG_NUM; $i++)
            {
                if (!isset($this->index[$i]))
                {
                    echo "lost package#$i\n";
                }
            }
        }
        $this->count = $this->recv_bytes = 0;
        $this->index = array();
    }
}

require 'config.php';
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(
    [
        'worker_num'            => 4,
        'dispatch_mode'         => 1,
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
$serv->on('workerStart', [$cb, 'onWorkerStart']);
$serv->on('Close', [$cb, 'onClose']);
$serv->start();
