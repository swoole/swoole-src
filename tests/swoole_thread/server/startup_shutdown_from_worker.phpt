--TEST--
swoole_thread/server: a worker can request shutdown immediately during manager-owned startup
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
        global $started, $exited, $masterStarted, $closing, $stop;
        $started = new Thread\Atomic(0);
        $exited = new Thread\Atomic(0);
        $masterStarted = new Thread\Atomic(0);
        $closing = new Thread\Atomic(0);
        $stop = new Thread\Queue();
        return [$started, $exited, $masterStarted, $closing, $stop];
    },
]);
$serv->on('Start', function () {
    global $masterStarted;
    $masterStarted->set(1);
});
$serv->on('WorkerStart', function ($server, $id) {
    [$started, $exited] = Thread::getArguments();
    $started->add();
    register_shutdown_function(function () use ($exited) {
        $exited->add();
    });
    if ($id === 0) {
        Assert::true($server->shutdown());
    }
});
$serv->on('BeforeShutdown', function () {
    global $masterStarted, $closing, $stop;
    Assert::same($masterStarted->get(), 1);
    $closing->set(1);
    $stop->push('stop', Thread\Queue::NOTIFY_ONE);
    echo "before shutdown\n";
});
$serv->on('ManagerStop', function () {
    [$started, $exited] = Thread::getArguments();
    Assert::true($started->get() >= 3);
    Assert::same($started->get(), $exited->get());
    echo "manager stopped\n";
});
$serv->on('Shutdown', function () {
    echo "DONE\n";
});
$serv->on('Receive', function () {});
$serv->on('Task', function () {});
$serv->addProcess(new Swoole\Process(function () {
    [$started, $exited, , $closing, $stop] = Thread::getArguments();
    $started->add();
    register_shutdown_function(function () use ($exited) {
        $exited->add();
    });
    if ($closing->get() === 0) {
        Assert::same($stop->pop(-1), 'stop');
    }
}));
$serv->start();
?>
--EXPECT--
before shutdown
manager stopped
DONE
