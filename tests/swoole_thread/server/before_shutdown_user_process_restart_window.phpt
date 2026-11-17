--TEST--
swoole_thread/server: user workers can restart during BeforeShutdown until the manager is notified
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
        global $queue, $starts, $restarted;
        $queue = new Swoole\Thread\Queue();
        $starts = new Swoole\Thread\Atomic(0);
        $restarted = new Swoole\Thread\Queue();
        return [$queue, $starts, $restarted];
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
    global $queue, $restarted;
    $queue->push('stop', Thread\Queue::NOTIFY_ONE);
    // The master notifies the manager only after this callback and its event loop finish.
    Assert::same($restarted->pop(5), 'restarted');
});
$serv->on('Receive', function () {});
$serv->on('Shutdown', function () {
    global $starts;
    Assert::true($starts->get() > 1);
    echo "restarted during BeforeShutdown\n";
});
$serv->addProcess(new Swoole\Process(function () {
    [$queue, $starts, $restarted] = Thread::getArguments();
    $generation = $starts->add();
    if ($generation > 1) {
        if ($generation === 2) {
            $restarted->push('restarted', Thread\Queue::NOTIFY_ONE);
        }
        return;
    }
    $queue->pop(-1);
}));
$serv->start();
?>
--EXPECT--
restarted during BeforeShutdown
