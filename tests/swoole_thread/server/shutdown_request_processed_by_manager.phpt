--TEST--
swoole_thread/server: worker replacement remains enabled until the manager receives shutdown
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

const EXIT_CODE = 237;

$serv = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_THREAD);
$serv->set([
    'worker_num' => 1,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $starts, $ready, $queue;
        $starts = new Thread\Atomic(0);
        $ready = new Thread\Atomic(0);
        $queue = new Thread\Queue();
        return [$starts, $ready, $queue];
    },
]);
$serv->on('Start', function () {
    global $ready;
    $ready->set(1);
});
$serv->on('WorkerError', function ($server, $workerId, $workerPid, $code) {
    [, $ready] = Thread::getArguments();
    Assert::same($code, EXIT_CODE);
    while ($ready->get() === 0) {
        usleep(1000);
    }
    // This callback runs on the manager. SIGTERM wakes the master; its shutdown command
    // cannot be consumed until the current worker-exit event has replaced its worker.
    Assert::true($server->shutdown());
    echo "shutdown signal sent\n";
});
$serv->on('BeforeShutdown', function () {
    global $queue;
    $queue->push('stop', Thread\Queue::NOTIFY_ONE);
});
$serv->on('Shutdown', function () {
    global $starts;
    Assert::true($starts->get() > 1);
    echo "worker replaced before manager received shutdown\n";
});
$serv->on('Receive', function () {});
$serv->addProcess(new Swoole\Process(function () {
    [$starts, , $queue] = Thread::getArguments();
    $generation = $starts->add();
    if ($generation === 1) {
        swoole_implicit_fn('bailout', EXIT_CODE);
    }
    if ($generation > 2) {
        return;
    }
    Assert::same($queue->pop(-1), 'stop');
}));
$serv->start();
?>
--EXPECT--
shutdown signal sent
worker replaced before manager received shutdown
