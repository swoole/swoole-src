--TEST--
swoole_thread/server: manager and worker reload requests run deferred callbacks on the manager
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

$serv = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_THREAD);
$serv->set([
    'worker_num' => 1,
    'task_worker_num' => 1,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $eventStarts, $taskStarts;
        $eventStarts = new Thread\Atomic(0);
        $taskStarts = new Thread\Atomic(0);
        return [
            new Thread\Atomic(0),
            new Thread\Atomic(0),
            new Thread\Atomic(0),
            new Thread\Atomic(0),
            new Thread\Atomic(0),
            new Thread\Queue(),
            $eventStarts,
            $taskStarts,
        ];
    },
]);
$serv->on('WorkerStart', function ($server, $id) {
    [, , , , , , $eventStarts, $taskStarts] = Thread::getArguments();
    ($id === 0 ? $eventStarts : $taskStarts)->add();
});
$serv->on('ManagerStart', function ($server) {
    [$managerId, $phase] = Thread::getArguments();
    $managerId->set(Thread::getNativeId());
    $phase->set(1);
    Assert::true($server->reload());
    // BeforeReload must wait until ManagerStart returns, as in process mode.
    Assert::same($phase->get(), 1);
    $phase->set(2);
});
$serv->on('BeforeReload', function () {
    [$managerId, $phase, $before] = Thread::getArguments();
    Assert::same(Thread::getNativeId(), $managerId->get());
    $round = $before->add();
    Assert::same($phase->get(), $round === 1 ? 2 : 4);
    $phase->set(3);
    echo "before reload {$round}\n";
});
$serv->on('AfterReload', function ($server) {
    [$managerId, $phase, $before, $after, , $queue] = Thread::getArguments();
    Assert::same(Thread::getNativeId(), $managerId->get());
    $round = $after->add();
    Assert::same($round, $before->get());
    Assert::same($phase->get(), 3);
    echo "after reload {$round}\n";
    if ($round === 1) {
        $phase->set(4);
        $queue->push('reload', Thread\Queue::NOTIFY_ONE);
    } else {
        $queue->push('done', Thread\Queue::NOTIFY_ONE);
    }
});
$serv->on('Receive', function () {});
$serv->on('Task', function () {});
$serv->on('Shutdown', function () {
    echo "DONE\n";
});
$serv->addProcess(new Swoole\Process(function () {
    global $serv;
    [, , , , $starts, $queue, $eventStarts, $taskStarts] = Thread::getArguments();
    if ($starts->add() > 1) {
        return;
    }
    Assert::same($queue->pop(-1), 'reload');
    // PHP and C++ both use only_reload_taskworker: true restricts the reload to task workers.
    Assert::true($serv->reload(only_reload_taskworker: true));
    Assert::same($queue->pop(-1), 'done');
    // AfterReload follows native thread creation; wait for their PHP WorkerStart callbacks.
    $deadline = microtime(true) + 5;
    while (($eventStarts->get() < 2 || $taskStarts->get() < 3) && microtime(true) < $deadline) {
        usleep(1000);
    }
    // Check the reload kind before shutdown can legitimately replace an exiting worker again.
    Assert::same($eventStarts->get(), 2);
    Assert::same($taskStarts->get(), 3);
    Assert::true($serv->shutdown());
}));
$serv->start();
?>
--EXPECT--
before reload 1
after reload 1
before reload 2
after reload 2
DONE
