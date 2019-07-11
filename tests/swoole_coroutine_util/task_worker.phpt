--TEST--
swoole_coroutine_util: sleep in Task-Worker
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
    echo trim($cli->recv()) . "\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort());
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 2,
        'log_file' => '/dev/null',
        'task_enable_coroutine' => true
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data) {
        $serv->task([$fd, 'sleep']);
    });

    $serv->on('task', function (swoole_server $serv, $task) {
        list($fd) = $task->data;
        co::sleep(0.2);
        $serv->send($fd, "sleep\r\n\r\n");
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
sleep
