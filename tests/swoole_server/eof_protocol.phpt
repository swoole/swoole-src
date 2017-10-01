--TEST--
swoole_server: (eof protocol) recv 100k packet

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

class EofServer extends TestServer
{
    protected $show_lost_package = true;
    function onReceive($serv, $fd, $reactor_id, $data)
    {
        $pkg = unserialize(rtrim($data));
        if ($pkg['index'] % 1000 == 0)
        {
            //echo "#{$pkg['index']} recv package. sid={$pkg['sid']}, length=" . strlen($data) . ", md5=".md5($data)."\n";
        }
        if (!isset($pkg['index']))
        {
            exit("error packet");
        }
        if ($pkg['index'] > self::PKG_NUM)
        {
            echo "invalid index #{$pkg['index']}\n";
        }
        $this->index[$pkg['index']] = true;
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
    if (!$client->connect('127.0.0.1', 9501, 2.0))
    {
        exit("connect failed\n");
    }
    $bytes = 0;
    $pkg_bytes = 0;

    for ($i = 0; $i < TestServer::PKG_NUM; $i++)
    {
        $len = rand(1000, 1024 * 128 - 8);
        $sid = rand(10000, 99999);

        $array['index'] = $i;
        $array['sid'] = $sid;
        $array['len'] = $len;
        $array['data'] = str_repeat('A', $len);
        $pkt = serialize($array) . "\r\n\r\n";
        $pkg_bytes += strlen($pkt);

//        if ($i % 1000 == 0 or $i > 99000)
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

//    echo "send ".TestServer::PKG_NUM." packet sucess, send $bytes bytes\n";
    $client->close();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new EofServer();
    $serv->set([
        'log_file' => '/dev/null',
        'package_eof' => "\r\n\r\n",
        'open_eof_split' => true,
        'worker_num' => 1,
        'package_max_length' => 1024 * 1024 * 2,
    ]);
    $serv->start();
};

$pm->childFirst();
//$pm->runParentFunc();
$pm->run();
?>
--EXPECTF--
end
Total count=100000, bytes=%d
