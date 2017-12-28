--TEST--
swoole_timer: call after in Task-Worker
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
$port = 9508;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($port, $pm)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);
    $cli->connect("127.0.0.1", $port, 5) or die("ERROR");

    $cli->send("task-01") or die("ERROR");
    for ($i = 0; $i < 4; $i++)
    {
        echo trim($cli->recv())."\n";
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new swoole_server("127.0.0.1", $port);
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 2,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data) {
        $serv->task([$fd, 'timer']);
    });

    $serv->on('task', function (swoole_server $serv, $task_id, $worker_id, $data) {
        list($fd) = $data;
        swoole_timer::after(500, function () use ($serv, $fd) {
            $serv->send($fd, "500\r\n\r\n");
            swoole_timer::after(300, function () use ($serv, $fd) {
                $serv->send($fd, "800\r\n\r\n");
            });
        });
        swoole_timer::after(1000, function () use ($serv, $fd) {
            $serv->send($fd, "1000\r\n\r\n");
        });
        swoole_timer::after(2000, function () use ($serv, $fd) {
            $serv->send($fd, "2000\r\n\r\n");
        });
    });

    $serv->on('finish', function (swoole_server $serv, $fd, $rid, $data)
    {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>

--EXPECT--
500
800
1000
2000
