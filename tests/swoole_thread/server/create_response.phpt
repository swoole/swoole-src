--TEST--
swoole_thread/server: create response
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

const SIZE = 2 * 1024 * 1024;
$port = get_constant_port(__FILE__);

$serv = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set(array(
    'worker_num' => 2,
    'task_worker_num' => 3,
    'log_level' => SWOOLE_LOG_ERROR,
    'init_arguments' => function () {
        global $queue, $atomic1, $atomic2;
        $queue = new Swoole\Thread\Queue();
        $atomic1 = new Swoole\Thread\Atomic(0);
        $atomic2 = new Swoole\Thread\Atomic(0);
        return [$queue, $atomic1, $atomic2];
    }
));
$serv->on('WorkerStart', function (Swoole\Server $serv, $workerId) use ($port) {
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
    if ($atomic1->add() == 5) {
        $queue->push("begin\n", Thread\Queue::NOTIFY_ALL);
    }
});
$serv->on('WorkerStop', function (Swoole\Server $serv, $workerId) {
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
    $atomic2->add();
});
$serv->on('Request', function ($req, $resp) use ($serv) {
    $resp->detach();
    $serv->task(['fd' => $resp->fd, 'uid' => $req->get['uid']]);
});
$serv->on('Task', function ($serv, $task_id, $worker_id, $data) {
    $response = Swoole\Http\Response::create($data['fd']);
    $response->end($data['uid']);
    $response->close();
});
$serv->on('shutdown', function () {
    global $queue, $atomic1, $atomic2;
    Assert::eq($atomic1->get(), 5);
    Assert::eq($atomic2->get(), 5);
    echo "shutdown\n";
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    global $port;
    echo $queue->pop(-1);
    $reqUid = uniqid();
    Assert::eq(file_get_contents('http://127.0.0.1:' . $port . '/?uid=' . $reqUid), $reqUid);
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECTF--
begin
done
shutdown
