--TEST--
swoole_runtime: stream_get_meta_data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function test($port) {
    $fp = stream_socket_client("tcp://127.0.0.1:".$port, $errno, $errstr, 2);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        //200ms
        stream_set_timeout($fp, 0, 200000);
        $http = "GET / HTTP/1.0\r\nAccept: */*User-Agent: Lowell-Agent\r\nHost: www.baidu.com\r\nConnection: Close\r\n\r\n";
        fwrite($fp, $http);
        $content = fread($fp, 1024);
        Assert::isEmpty($content);
        $res = stream_get_meta_data($fp);
        Assert::false($res['eof']);
        Assert::true($res['blocked']);
        Assert::true($res['timed_out']);
        fclose($fp);
    }
}

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $port = $pm->getFreePort();
    test($port);
    swoole_runtime::enableCoroutine();
    go(function() use($port) {
        test($port);
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_BASE);
    $socket = $serv->getSocket();
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data) use ($socket)
    {
        //donot send any
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
