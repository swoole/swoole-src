--TEST--
swoole_thread/server: event workers still restart during BeforeShutdown after external SIGTERM
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
    'task_worker_num' => 0,
    'log_file' => '/dev/null',
    'log_level' => SWOOLE_LOG_ERROR,
    'init_arguments' => function () {
        global $starts, $restarted;
        $starts = new Thread\Atomic(0);
        $restarted = new Thread\Queue();
        return [$starts, $restarted];
    },
]);
$serv->on('WorkerStart', function ($server, $id) {
    if ($id === 0) {
        [$starts, $restarted] = Thread::getArguments();
        if ($starts->add() === 2) {
            $restarted->push('restarted', Thread\Queue::NOTIFY_ONE);
        }
    }
});
$serv->on('Start', function ($server) {
    Timer::tick(10, function ($timerId) use ($server) {
        global $starts;
        if ($starts->get() === 1) {
            Timer::clear($timerId);
            Assert::true(Swoole\Process::kill($server->master_pid, SIGTERM));
        }
    });
});
$serv->on('BeforeShutdown', function ($server) {
    global $restarted;
    Assert::true($server->stop(0));
    Assert::same($restarted->pop(5), 'restarted');
});
$serv->on('Receive', function () {});

$serv->on('Shutdown', function () {
    global $starts;
    echo 'starts: ', $starts->get(), "\n";
});
$serv->start();
?>
--EXPECT--
starts: 2
