--TEST--
swoole_server/task: task callback
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Server;
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);
//    $cli->set(['open_eof_split' => true, 'package_eof' => "\r\n\r\n"]);
    $cli->connect('127.0.0.1', $pm->getFreePort(), 0.5) or die("ERROR");

    $cli->send("task-01") or die("ERROR");

    $res = json_decode(trim($cli->recv()), true);
    Assert::same($res['code'], 0);
    Assert::same($res['message'], 'hello world');

    echo "SUCCESS\n";

    $res = json_decode(trim($cli->recv()), true);
    Assert::same($res['code'], 0);
    Assert::same($res['message'], 'hello world');
    echo "SUCCESS\n";

    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    ini_set('swoole.display_errors', 'Off');
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 2,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data)
    {
        $serv->task(['type' => 'array', 'value' => $data], -1, function ($serv, $taskId, $data) use ($fd)  {
            $serv->send($fd, json_encode($data)."\r\n\r\n");
        });
        $serv->task(['type' => 'array', 'value' => $data, 'worker_id' => 0], 0, function ($serv, $taskId, $data) use ($fd)  {
            $serv->send($fd, json_encode($data)."\r\n\r\n");
        });
    });

    $serv->on('task', function (Server $serv, $task_id, $worker_id, $data)
    {
        return array("code" => 0, 'message' => 'hello world', 'sid' => uniqid());
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
SUCCESS
SUCCESS
