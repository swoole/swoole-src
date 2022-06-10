--TEST--
swoole_timer: call tick timer in Task-Worker
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
    for ($i = 0; $i < 3; $i++)
    {
        echo trim($cli->recv())."\n";
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort());
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
        static $i = 0;
        Swoole\Timer::tick(1, function () use(&$i, $serv) {
            $i++;
            if ($i % 500 == 499) {
                $serv->send(1, "timer-$i\r\n\r\n");
            }
        });
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
timer-499
timer-999
timer-1499
