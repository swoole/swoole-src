--TEST--
swoole_server/task: task in user process
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(60);
$pm->parentFunc = function ($pid) use ($pm) {
    echo "SUCCESS\n";
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
    ));

    $process = new \Swoole\Process(function ($process) use ($serv)
    {
        $serv->task(['type' => 'array', 'value' => 'user process']);
        sleep(60);
    });

    $serv->addProcess($process);

    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {

    });

    $serv->on('task', function (swoole_server $serv, $task_id, $worker_id, $data) use($pm)
    {
        Assert::false($serv->finish("OK"));
        $pm->wakeup();
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
SUCCESS
