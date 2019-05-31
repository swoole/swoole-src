--TEST--
swoole_coroutine_server: (length protocol) 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/TestServer_Co.php';

class PkgServer_co_length_1 extends TestServer_Co
{
    protected $show_lost_package = true;

    function onWorkerStart()
    {
        global $pm;
        $pm->wakeup();
    }

    function onClose()
    {
        parent::onClose();
        $this->serv->shutdown();
    }
}

PkgServer_co_length_1::$random_bytes = true;
PkgServer_co_length_1::$pkg_num = 10000;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $client = new swoole_client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', $pm->getFreePort()))
    {
        exit("connect failed\n");
    }

    $bytes = 0;
    $pkg_bytes = 0;

    for ($i = 0; $i < PkgServer_co_length_1::$pkg_num; $i++)
    {
//        if ($i % 1000 == 0)
//        {
//            echo "#{$i} send package. sid={$sid}, length=" . ($len + 10) . ", total bytes={$pkg_bytes}\n";
//        }
        if (!$client->send(PkgServer_co_length_1::getPacket()))
        {
            break;
        }
        $bytes += 2;
    }

    $recv = $client->recv();
    echo $recv;
    //echo "send ".TestServer::PKG_NUM." packet sucess, send $bytes bytes\n";
    $client->close();
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $serv = new PkgServer_co_length_1($pm->getFreePort(), false);
        $serv->start();
    });
    swoole_event::wait();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTREGEX--
end
Total count=100000?, bytes=\d+
