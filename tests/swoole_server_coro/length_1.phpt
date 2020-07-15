--TEST--
swoole_server_coro: (length protocol) 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use SwooleTest\LengthServer;

class TestServer_5 extends LengthServer
{
    protected $show_lost_package = false;

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

TestServer_5::$random_bytes = true;
TestServer_5::$pkg_num = IS_IN_TRAVIS ? 1000 : 10000;

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

    for ($i = 0; $i < TestServer_5::$pkg_num; $i++)
    {
//        if ($i % 1000 == 0)
//        {
//            echo "#{$i} send package. sid={$sid}, length=" . ($len + 10) . ", total bytes={$pkg_bytes}\n";
//        }
        if (!$client->send(TestServer_5::getPacket()))
        {
            echo "send [$i] failed.\n";
            break;
        }
        $bytes += 2;
    }

    $recv = $client->recv();
    echo $recv;
    //echo "send ".TestServer::$PKG_NUM." packet sucess, send $bytes bytes\n";
    $client->close();
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $serv = new TestServer_5($pm->getFreePort(), false);
        $serv->start();
    });
    swoole_event::wait();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
end
Total count=%d, bytes=%d
