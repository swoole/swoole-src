--TEST--
swoole_server/task: task callback is null
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->set(['open_eof_check' => true, "package_eof" => "\r\n\r\n"]);
    $cli->connect('127.0.0.1', $pm->getFreePort(), 0.5) or die("ERROR");

    $cli->send("task-01") or die("ERROR");
    $res = json_decode(trim($cli->recv()), true);
    Assert::same($res['code'], 0);
    Assert::same($res['message'], 'hello world');
    echo "SUCCESS\n";

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    ini_set('swoole.display_errors', 'Off');
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set(array(
        "worker_num" => 1,
        'task_worker_num' => 2,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {
        $serv->task(['type' => 'array', 'value' => $data, 'fd' => $fd], -1, null);
    });
    $serv->on('task', function (Server $serv, $task_id, $worker_id, $data) {
        return array("code" => 0, 'message' => 'hello world', 'sid' => uniqid(), 'fd' => $data['fd']);
    });
    $serv->on('finish', function (Server $serv, $task_id, $data) {
        $serv->send($data['fd'], json_encode($data) . "\r\n\r\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
