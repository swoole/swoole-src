--TEST--
swoole_http_client: websocket client with bad protocol
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
const N = 128;
$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $cli = new swoole_http_client('127.0.0.1', 9501);
    $cli->count = 0;
    $cli->on('close', function ($cli)
    {
        echo "close\n";
    });
    $cli->on('error', function ($cli)
    {
        echo "error\n";
    });
    $cli->on('Message', function ($cli, $frame)
    {
    });
    $cli->upgrade('/websocket', function ($cli)
    {
        @$cli->push(str_repeat('A', rand(8192, 65536)));
        assert(swoole_last_error() == 8504);
    });
    swoole_event::wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server("127.0.0.1", 9501);
    $serv->set(['log_file' => '/dev/null']);
    $serv->on('Receive', function ($serv, $fd, $rid, $data)
    {
        $serv->send($fd, "data");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
close

