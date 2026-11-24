--TEST--
swoole_thread/server: ManagerStop runs after event, task and user workers finish request shutdown
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Timer;

$serv = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_THREAD);
$serv->set([
    'worker_num' => 1,
    'task_worker_num' => 1,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $ready, $exited, $managerStopped, $queue, $stopping;
        $ready = new Thread\Atomic(0);
        $exited = new Thread\Atomic(0);
        $managerStopped = new Thread\Atomic(0);
        $queue = new Thread\Queue();
        $stopping = new Thread\Atomic(0);
        return [$ready, $exited, $managerStopped, $queue, $stopping];
    },
]);
$serv->on('WorkerStart', function () {
    [$ready, $exited] = Thread::getArguments();
    register_shutdown_function(function () use ($exited) {
        $exited->add();
    });
    $ready->add();
});
$serv->on('Start', function ($server) {
    Timer::tick(10, function ($timerId) use ($server) {
        global $ready;
        if ($ready->get() === 3) {
            Timer::clear($timerId);
            Assert::true($server->shutdown());
        }
    });
});
$serv->on('BeforeShutdown', function () {
    global $queue, $stopping;
    $stopping->set(1);
    $queue->push('stop', Thread\Queue::NOTIFY_ONE);
});
$serv->on('ManagerStop', function ($server) {
    [$ready, $exited, $managerStopped] = Thread::getArguments();
    Assert::true($exited->get() >= 3);
    Assert::same($exited->get(), $ready->get());
    Assert::false($server->reload());
    $managerStopped->set(1);
    echo "manager stopped after all workers\n";
});
$serv->on('Shutdown', function () {
    global $managerStopped;
    Assert::same($managerStopped->get(), 1);
    echo "DONE\n";
});
$serv->on('Receive', function () {});
$serv->on('Task', function () {});
$serv->addProcess(new Swoole\Process(function () {
    [$ready, $exited, , $queue, $stopping] = Thread::getArguments();
    register_shutdown_function(function () use ($exited) {
        $exited->add();
    });
    $ready->add();
    if ($stopping->get() === 0) {
        Assert::same($queue->pop(-1), 'stop');
    }
}));
$serv->start();
?>
--EXPECT--
manager stopped after all workers
DONE
