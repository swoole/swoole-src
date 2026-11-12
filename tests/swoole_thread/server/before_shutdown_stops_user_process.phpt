--TEST--
swoole_thread/server: a user process stopped from BeforeShutdown is not started again
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
    'log_level' => SWOOLE_LOG_ERROR,
    'init_arguments' => function () {
        global $queue, $starts;
        $queue = new Swoole\Thread\Queue();
        $starts = new Swoole\Thread\Atomic(0);
        return [$queue, $starts];
    },
]);
$serv->on('Start', function (Swoole\Server $serv) {
    global $starts;
    Timer::tick(10, function (int $timerId) use ($serv, $starts) {
        if ($starts->get() > 0) {
            Timer::clear($timerId);
            $serv->shutdown();
        }
    });
});
$serv->on('BeforeShutdown', function () {
    global $queue;
    $queue->push('stop', Thread\Queue::NOTIFY_ONE);
    // Still running when the user process exits
    usleep(300 * 1000);
});
$serv->on('Receive', function () {});
$serv->on('Shutdown', function () {
    global $starts;
    echo 'starts: ', $starts->get(), PHP_EOL;
});
$serv->addProcess(new Swoole\Process(function () {
    [$queue, $starts] = Thread::getArguments();
    if ($starts->add() > 1) {
        return;
    }
    $queue->pop(-1);
}));
$serv->start();
?>
--EXPECT--
starts: 1
