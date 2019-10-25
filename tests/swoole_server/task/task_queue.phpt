--TEST--
swoole_server/task: task queue
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
const N = 2048;
use Swoole\Server;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect('127.0.0.1', $pm->getFreePort(), 10) or die("ERROR");
    $cli->send("task-01") or die("ERROR");
    echo $cli->recv();
    $cli->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data)
    {
        for ($i = 0; $i < 2048; $i++)
        {
            $data = array('id' => $i, 'fd' => $fd, 'data' => RandStr::getBytes(rand(2048, 4096)));
            if ($serv->task($data) === false)
            {
                $serv->send($fd, "ERROR\n");
                return;
            }
        }
    });

    $serv->on('task', function (Server $serv, $task_id, $worker_id, $data)
    {
        if ($task_id == 0)
        {
            sleep(1);
        }
        if ($task_id != $data['id'])
        {
            echo "ERROR, $task_id, {$data['id']}\n";
        }
        if ($data['id'] == N - 1)
        {
            $serv->send($data['fd'], "OK");
        }
    });

    $serv->on('finish', function (Server $serv, $fd, $rid, $data)
    {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
