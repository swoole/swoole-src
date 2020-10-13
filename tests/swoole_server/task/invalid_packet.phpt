--TEST--
swoole_server/task: invalid packet
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_function_not_exist('msg_get_queue');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
const MSGQ_KEY = 0x70001001;

$file = __DIR__.'/tmp.log';
use Swoole\Server;

$result = new Swoole\Atomic(0);
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $data = '{"tid":17732683638813521,"out_trade_no":"dm5601993521","runMethod":"\\Action\\Mpay\\Uni\\UniApiV3Act:jsonDrive"}';
    $queueId = msg_get_queue(MSGQ_KEY);
    if ($queueId === false) {
        throw new \Swoole\Exception("msg_get_queue() failed.");
    }
    Assert::true(msg_send($queueId, 1, $data));
    Assert::true(msg_send($queueId, 1, Swoole\Server\Task::pack($data), false));
    $pm->wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $file, $result) {
    ini_set('swoole.display_errors', 'Off');
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        "worker_num" => 2,
        'task_worker_num' => 1,
        'task_ipc_mode' => 3,
        'message_queue_key' => MSGQ_KEY,
        'log_file' => $file,
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {

    });
    $serv->on('task', function (Server $serv, $task_id, $worker_id, $data) use ($pm, $result) {
        $pm->wakeup();
        $result->add(1);
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();

// echo file_get_contents($file);
Assert::true(swoole_string(file_get_contents($file))->contains('ProcessPool_worker_loop: bad task packet'));
unlink($file);
Assert::eq($result->get(), 1);
?>
--EXPECT--
