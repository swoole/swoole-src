--TEST--
swoole_server: dispatch_mode = 3
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_docker('unknown reason in docker');
?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
const REQ_N = 10000;
const CLIENT_N = 16;
const WORKER_N = 16;

global $stats;
$stats = array();
$count = 0;
$port = get_one_free_port();

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port)
{
    global $count, $stats;
    for ($i = 0; $i < CLIENT_N; $i++)
    {
        $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
        $cli->set([
            'package_eof' => "\r\n\r\n",
            'open_eof_split' => true,
        ]);
        $cli->count = 0;
        $cli->on("connect", function (swoole_client $cli)
        {
            for ($i = 0; $i < REQ_N; $i++)
            {
                $cli->send("hello world\r\n\r\n");
            }
        });
        $cli->on("receive", function (swoole_client $cli, $data)
        {
            global $stats;
            $wid = trim($data);
            if (isset($stats[$wid]))
            {
                $stats[$wid]++;
            }
            else
            {
                $stats[$wid] = 1;
            }
            $cli->count++;
            if ($cli->count == REQ_N)
            {
                $cli->close();
            }
        });
        $cli->on("error", function (swoole_client $cli)
        {
            echo "error\n";
        });
        $cli->on("close", function (swoole_client $cli)
        {

        });
        $cli->connect("127.0.0.1", $port, 0.1);
    }
    swoole_event::wait();
    swoole_process::kill($pid);
    assert($stats[10] < 500);
    assert($stats[5] < 500);
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new swoole_server("127.0.0.1", $port, SWOOLE_PROCESS);
    $serv->set(array(
        "worker_num" => WORKER_N,
        'dispatch_mode' => 3,
        'package_eof' => "\r\n\r\n",
        'open_eof_split' => true,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        if ($serv->worker_id == 10 or $serv->worker_id == 5)
        {
            usleep(5000);
        }
        $serv->send($fd, $serv->worker_id . "\r\n\r\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
