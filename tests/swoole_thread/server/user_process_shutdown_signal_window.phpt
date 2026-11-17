--TEST--
swoole_thread/server: user-worker shutdown uses SIGTERM and preserves the signal-dispatch restart window
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
        global $state, $starts;
        $state = new Swoole\Thread\Atomic(0);
        $starts = new Swoole\Thread\Atomic(0);
        return [$state, $starts];
    },
]);
$serv->on('Start', function () {
    global $state;
    // Keep the master thread busy, so the user process exits before the master handles the shutdown signal
    Timer::tick(10, function (int $timerId) use ($state) {
        if ($state->get() === 1) {
            Timer::clear($timerId);
            $state->set(2);
            $deadline = microtime(true) + 5;
            while ($state->get() !== 3 && microtime(true) < $deadline) {
                usleep(1000);
            }
            Assert::same($state->get(), 3);
        }
    });
});
$serv->on('Receive', function () {});
$serv->on('Shutdown', function () {
    global $starts;
    Assert::true($starts->get() > 1);
    echo "restarted before master handled SIGTERM\n";
});
$serv->addProcess(new Swoole\Process(function () use ($serv) {
    [$state, $starts] = Thread::getArguments();
    if ($starts->add() > 1) {
        $state->set(3);
        return;
    }
    $state->set(1);
    while ($state->get() !== 2) {
        usleep(1000);
    }
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
restarted before master handled SIGTERM
