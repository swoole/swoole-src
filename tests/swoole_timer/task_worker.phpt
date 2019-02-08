--TEST--
swoole_timer: call after in Task-Worker
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);
    $cli->connect('127.0.0.1', $pm->getFreePort(), 5) or die("ERROR");

    $cli->send("task-01") or die("ERROR");
    for ($i = 0; $i < 5; $i++)
    {
        echo trim($cli->recv())."\n";
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort());
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 1,
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
            $serv->send($fd, "1000[1]\r\n\r\n");
        });
        swoole_timer::after(1000, function () use ($serv, $fd) {
            $serv->send($fd, "1000[2]\r\n\r\n");
        });
        swoole_timer::after(500, function () use ($serv, $fd) {
            $serv->send($fd, "500[2]\r\n\r\n");
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
500[2]
800
1000[1]
1000[2]
