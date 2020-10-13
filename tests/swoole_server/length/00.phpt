--TEST--
swoole_server/length: (length protocol) recv 100k packet
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require __DIR__ . '/../../include/api/swoole_server/TestServer.php';

TestServer::$PKG_NUM = MAX_PACKET_NUM;

class PkgServer extends TestServer
{
    protected $show_lost_package = false;

    function onReceive($serv, $fd, $reactor_id, $data)
    {
        $header = unpack('Nlen/Nindex/Nsid', substr($data, 0, 12));
        if ($header['index'] % 1000 == 0) {
            //echo "#{$header['index']} recv package. sid={$header['sid']}, length=" . strlen($data) . ", bytes={$this->recv_bytes}\n";
        }
        if ($header['index'] > self::$PKG_NUM) {
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

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }

    $bytes = 0;
    $pkg_bytes = 0;

    for ($i = 0; $i < TestServer::$PKG_NUM; $i++) {
        $len = rand(1000, 1024 * 128 - 8);
        $sid = rand(10000, 99999);

        $pkt = pack('NNN', $len + 8, $i, $sid);
        $pkt .= str_repeat('A', $len);

        $pkg_bytes += strlen($pkt);

//        if ($i % 1000 == 0)
//        {
//            echo "#{$i} send package. sid={$sid}, length=" . ($len + 10) . ", total bytes={$pkg_bytes}\n";
//        }
        if (!$client->send($pkt)) {
            break;
        }
        $bytes += strlen($pkt);
    }

    $recv = $client->recv();
    echo $recv;
    //echo "send ".TestServer::$PKG_NUM." packet sucess, send $bytes bytes\n";
    $client->close();

    usleep(1);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    $serv = new PkgServer($pm->getFreePort(), true);
    $serv->set([
        'worker_num' => 1,
        //'dispatch_mode'         => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
        'task_worker_num' => 0
    ]);
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTREGEX--
end
Total count=\d+, bytes=\d+
