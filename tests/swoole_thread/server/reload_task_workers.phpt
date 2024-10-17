--TEST--
swoole_thread/server: reload task workers
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
    'worker_num' => 3,
    'task_worker_num' => 4,
    'log_level' => SWOOLE_LOG_ERROR,
    'log_file' => '/dev/null',
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
    $c = $atomic1->add();
    if ($c == 11) {
        $queue->push("begin 2\n", Thread\Queue::NOTIFY_ALL);
    }
});
$serv->on('WorkerStop', function (Swoole\Server $serv, $workerId) {
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
    $atomic2->add();
});
$serv->on('Request', function ($req, $resp) use ($serv) {
});
$serv->on('Task', function ($serv, $task_id, $worker_id, $data) {
});
$serv->on('managerStart', function ($serv) {
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
    $queue->push("begin 1\n", Thread\Queue::NOTIFY_ALL);
});
$serv->on('beforeReload', function ($serv) {
    echo 'beforeReload', PHP_EOL;
});
$serv->on('afterReload', function ($serv) {
    echo 'afterReload', PHP_EOL;
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
});
$serv->on('shutdown', function () {
    global $queue, $atomic1, $atomic2;
    echo 'shutdown', PHP_EOL;
    Assert::eq($atomic1->get(), 11);
    Assert::eq($atomic2->get(), 11);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    echo $queue->pop(-1);
    $serv->reload(true);
    echo $queue->pop(-1);
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
begin 1
beforeReload
afterReload
begin 2
done
shutdown

