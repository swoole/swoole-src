--TEST--
swoole_thread/server: user processes keep the main thread's signal handler
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Process;
use Swoole\Thread;

$port = get_constant_port(__FILE__);

$serv = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set([
    'worker_num' => 1,
    'log_level' => SWOOLE_LOG_ERROR,
    'enable_coroutine' => false,
    'init_arguments' => function () {
        global $queue, $atomic;
        $queue = new Thread\Queue();
        $atomic = new Thread\Atomic(0);
        return [$queue, $atomic];
    },
]);
$serv->on('receive', function () {});
$serv->on('start', function () {
    global $queue;
    Process::signal(SIGURG, function () use ($queue) {
        echo "signal\n";
        $queue->push('handled', Thread\Queue::NOTIFY_ALL);
    });
    $queue->push('registered', Thread\Queue::NOTIFY_ALL);
});
$serv->addProcess(new Process(function () use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    // The first run exits after the handler is registered, so the process ends and starts again
    if ($atomic->add() == 1) {
        $queue->pop(-1);
        return;
    }
    Process::kill(getmypid(), SIGURG);
    $queue->pop(2);
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
signal
