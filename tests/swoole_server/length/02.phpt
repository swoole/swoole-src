--TEST--
swoole_server/length: (length protocol) no body
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require __DIR__ . '/../../include/api/swoole_server/TestServer.php';

TestServer::$PKG_NUM = MAX_PACKET_NUM;

class PkgServer_2 extends TestServer
{
    protected $show_lost_package = false;

    function onReceive($serv, $fd, $reactor_id, $data)
    {
        static $index = 0;
        $header = unpack('nlen', $data);
        Assert::same(strlen($data), 2);
        Assert::same($header['len'], 2);
        if ($index % 1000 == 0) {
            //echo "#{$header['index']} recv package. sid={$header['sid']}, length=" . strlen($data) . ", bytes={$this->recv_bytes}\n";
        }
        if ($index > self::$PKG_NUM) {
            echo "invalid index #{$index}\n";
        }
        $this->index[$index] = true;
        $index++;
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
//        if ($i % 1000 == 0)
//        {
//            echo "#{$i} send package. sid={$sid}, length=" . ($len + 10) . ", total bytes={$pkg_bytes}\n";
//        }
        if (!$client->send(pack('n', 2))) {
            break;
        }
        $bytes += 2;
    }

    $recv = $client->recv();
    echo $recv;
    //echo "send ".TestServer::$PKG_NUM." packet sucess, send $bytes bytes\n";
    $client->close();

    usleep(1);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    $serv = new PkgServer_2($pm->getFreePort(), true);
    $serv->set([
        'worker_num' => 1,
        //'dispatch_mode'         => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'n',
        'package_length_offset' => 0,
        'package_body_offset' => 0,
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
