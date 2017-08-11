--TEST--
swoole_server: task callback
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
$pm->parentFunc = function ($pid) use ($port)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);
//    $cli->set(['open_eof_split' => true, 'package_eof' => "\r\n\r\n"]);
    $cli->connect("127.0.0.1", $port, 0.5) or die("ERROR");

    $cli->send("task-01") or die("ERROR");

    $res = json_decode(trim($cli->recv()), true);
    assert($res['code'] == 0);
    assert($res['message'] == 'hello world');

    echo "SUCCESS\n";

    $res = json_decode(trim($cli->recv()), true);
    assert($res['code'] == 0);
    assert($res['message'] == 'hello world');
    echo "SUCCESS\n";

    swoole_process::kill($pid);
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
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $serv->task(['type' => 'array', 'value' => $data], -1, function ($serv, $taskId, $data) use ($fd)  {
            $serv->send($fd, json_encode($data)."\r\n\r\n");
        });
        $serv->task(['type' => 'array', 'value' => $data, 'worker_id' => 0], 0, function ($serv, $taskId, $data) use ($fd)  {
            $serv->send($fd, json_encode($data)."\r\n\r\n");
        });
    });

    $serv->on('task', function (swoole_server $serv, $task_id, $worker_id, $data)
    {
        return array("code" => 0, 'message' => 'hello world', 'sid' => uniqid());
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
SUCCESS
