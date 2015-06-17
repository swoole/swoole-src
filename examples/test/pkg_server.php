<?php
require __DIR__.'/TestServer.php';

class PkgServer extends TestServer
{
    function onReceive($serv, $fd, $from_id, $data)
    {
        $header = unpack('nlen/Nindex/Nsid', substr($data, 0, 10));
        if ($header['index'] % 1000 == 0)
        {
            echo "#{$header['index']} recv package. sid={$header['sid']}, length=" . strlen($data) . "\n";
        }
        $this->count++;
        if ($header['index'] > self::PKG_NUM)
        {
            echo "invalid index #{$header['index']}\n";
        }
        $this->recv_bytes += strlen($data);
        $this->index[$header['index']] = true;
    }
}

$serv = new PkgServer();
$serv->set([
    'worker_num'            => 4,
    'dispatch_mode'         => 1,
    'open_length_check'     => true,
    'package_max_length'    => 81920,
    'package_length_type'   => 'n', //see php pack()
    'package_length_offset' => 0,
    'package_body_offset'   => 2,
    'task_worker_num'       => 0
]);
$serv->start();
