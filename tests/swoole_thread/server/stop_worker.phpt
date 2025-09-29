--TEST--
swoole_thread/server: stop worker
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

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
    if ($req->server['request_uri'] == '/stop') {
        $serv->stop($req->get['worker'] ?? 0);
        $resp->end("OK\n");
    }
});
$serv->on('Task', function ($serv, $task_id, $worker_id, $data) {

});
$serv->on('shutdown', function () {
    global $queue, $atomic1, $atomic2;
    echo 'shutdown', PHP_EOL;
    Assert::eq($atomic1->get(), 7);
    Assert::eq($atomic2->get(), 7);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    global $port;
    echo $queue->pop(-1);

    echo file_get_contents('http://127.0.0.1:' . $port . '/stop?worker=' . random_int(0, 1));
    echo file_get_contents('http://127.0.0.1:' . $port . '/stop?worker=' . random_int(2, 4));

    sleep(1);
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECTF--
begin
OK
OK
done
shutdown

