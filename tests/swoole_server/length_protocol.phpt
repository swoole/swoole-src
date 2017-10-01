--TEST--
swoole_server: (length protocol) recv 100k packet

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . '/../include/api/swoole_server/TestServer.php';

class PkgServer extends TestServer
{
    protected $show_lost_package = true;
    function onReceive($serv, $fd, $reactor_id, $data)
    {
        $header = unpack('Nlen/Nindex/Nsid', substr($data, 0, 12));
        if ($header['index'] % 1000 == 0)
        {
            //echo "#{$header['index']} recv package. sid={$header['sid']}, length=" . strlen($data) . ", bytes={$this->recv_bytes}\n";
        }
        if ($header['index'] > self::PKG_NUM)
        {
            echo "invalid index #{$header['index']}\n";
        }
        $this->index[$header['index']] = true;
    }

    function onWorkerStart($serv, $wid)
    {
        global $pm;
        $pm->wakeup();
    }
}

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', 9501))
    {
        exit("connect failed\n");
    }

    $bytes = 0;
    $pkg_bytes = 0;

    for ($i = 0; $i < TestServer::PKG_NUM; $i++)
    {
        $len = rand(1000, 1024 * 128 - 8);
        $sid = rand(10000, 99999);

        $pkt = pack('NNN', $len + 8, $i, $sid);
        $pkt .= str_repeat('A', $len);

        $pkg_bytes += strlen($pkt);

//        if ($i % 1000 == 0)
//        {
//            echo "#{$i} send package. sid={$sid}, length=" . ($len + 10) . ", total bytes={$pkg_bytes}\n";
//        }
        if (!$client->send($pkt))
        {
            break;
        }
        $bytes += strlen($pkt);
    }

    $recv = $client->recv();
    echo $recv;
    //echo "send ".TestServer::PKG_NUM." packet sucess, send $bytes bytes\n";
    $client->close();

    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server(UDP_SERVER_HOST, UDP_SERVER_PORT, SWOOLE_BASE, SWOOLE_SOCK_UDP);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null']);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });

    $serv = new PkgServer(true);
    $serv->set([
        'worker_num'            => 1,
        //'dispatch_mode'         => 1,
        'open_length_check'     => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type'   => 'N',
        'package_length_offset' => 0,
        'package_body_offset'   => 4,
        'task_worker_num'       => 0
    ]);
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
end
Total count=100000, bytes=%d
