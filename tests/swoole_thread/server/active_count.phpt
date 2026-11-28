--TEST--
swoole_thread/server: manager, event, task and user threads each own one PHP thread count
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

$server = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_THREAD);
$server->set([
    'worker_num' => 1,
    'task_worker_num' => 1,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $ready, $managerReady, $stopping, $release;
        $ready = new Thread\Atomic(0);
        $managerReady = new Thread\Atomic(0);
        $stopping = new Thread\Atomic(0);
        $release = new Thread\Queue();
        return [$ready, $managerReady, $stopping, $release];
    },
]);
$server->on('WorkerStart', function () {
    [$ready] = Thread::getArguments();
    $ready->add();
});
$server->on('ManagerStart', function () {
    [, $managerReady] = Thread::getArguments();
    // Creation of all three workers is complete, even if their PHP requests have not entered yet.
    Assert::same(Thread::activeCount(), 5);
    $managerReady->set(1);
});
$server->on('Start', function ($server) {
    Timer::tick(10, function ($timerId) use ($server) {
        global $ready, $managerReady;
        if ($ready->get() !== 3 || $managerReady->get() !== 1) {
            return;
        }
        Timer::clear($timerId);
        Assert::same(Thread::activeCount(), 5);
        Assert::true($server->shutdown());
    });
});
$server->on('BeforeShutdown', function () {
    global $stopping, $release;
    $stopping->set(1);
    $release->push('stop', Thread\Queue::NOTIFY_ONE);
});
$server->on('ManagerStop', function () {
    // The manager remains counted until its own PHP request and TSRM cleanup finish.
    Assert::same(Thread::activeCount(), 2);
});
$server->on('Shutdown', function () {
    Assert::same(Thread::activeCount(), 1);
    echo "DONE\n";
});
$server->on('Receive', function () {});
$server->on('Task', function () {});
$server->addProcess(new Swoole\Process(function () {
    [$ready, , $stopping, $release] = Thread::getArguments();
    $ready->add();
    // A replacement created in the shutdown notification window must not wait for another stop token.
    if ($stopping->get() === 0) {
        Assert::same($release->pop(-1), 'stop');
    }
}));
Assert::true($server->start());
?>
--EXPECT--
DONE
