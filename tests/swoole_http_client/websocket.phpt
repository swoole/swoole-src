--TEST--
swoole_http_client: websocket client send 128 messages
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
        $cli->count++;
        if ($cli->count == N)
        {
            echo "OK\n";
            $cli->close();
        }
    });
    $cli->upgrade('/websocket', function ($cli)
    {
        for ($i = 0; $i < N; $i++)
        {
            $cli->push(str_repeat('A', rand(8192, 65536)));
        }
    });
    swoole_event::wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_websocket_server("127.0.0.1", 9501);
    $serv->set(['log_file' => '/dev/null']);
    $serv->count = 0;
    $serv->on('Open', function ($swoole_server, $req)
    {
    });
    $serv->on("WorkerStart", function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $serv->on('Message', function ($serv, $frame)
    {
        $serv->count++;
        if ($serv->count == N)
        {
            for ($i = 0; $i < N; $i++)
            {
                $serv->push($frame->fd, str_repeat('B', rand(8192, 65536)));
            }
        }
    });
    $serv->on('Close', function ($swoole_server, $fd)
    {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
close
