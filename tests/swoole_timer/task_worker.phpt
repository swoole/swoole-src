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
    $cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
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
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Swoole\Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
        $serv->task([$fd, 'timer']);
    });

    $serv->on('task', function (Swoole\Server $serv, $task_id, $worker_id, $data) {
        list($fd) = $data;
        Swoole\Timer::after(500, function () use ($serv, $fd) {
            $serv->send($fd, "500\r\n\r\n");
            Swoole\Timer::after(300, function () use ($serv, $fd) {
                $serv->send($fd, "800\r\n\r\n");
            });
        });
        Swoole\Timer::after(1000, function () use ($serv, $fd) {
            $serv->send($fd, "1000[1]\r\n\r\n");
        });
        Swoole\Timer::after(1000, function () use ($serv, $fd) {
            $serv->send($fd, "1000[2]\r\n\r\n");
        });
        Swoole\Timer::after(500, function () use ($serv, $fd) {
            $serv->send($fd, "500[2]\r\n\r\n");
        });
        Swoole\Timer::after(2000, function () use ($serv, $fd) {
            $serv->send($fd, "2000\r\n\r\n");
        });
    });

    $serv->on('finish', function (Swoole\Server $serv, $fd, $rid, $data)
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
