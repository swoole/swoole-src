--TEST--
swoole_thread/server: timers and unrelated exits cannot advance an in-flight reload
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
    'worker_num' => 3,
    'reload_async' => true,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $starts, $stops, $userStarts, $releaseFirst, $releaseSecond, $releaseUser, $stopping, $after, $errors;
        $starts = [new Thread\Atomic(), new Thread\Atomic(), new Thread\Atomic()];
        $stops = [new Thread\Atomic(), new Thread\Atomic(), new Thread\Atomic()];
        $userStarts = new Thread\Atomic();
        $releaseFirst = new Thread\Atomic();
        $releaseSecond = new Thread\Atomic();
        $releaseUser = new Thread\Atomic();
        $stopping = new Thread\Atomic();
        $after = new Thread\Atomic();
        $errors = new Thread\Atomic();
        return [$starts, $stops, $userStarts, $releaseFirst, $releaseSecond, $releaseUser, $stopping, $after, $errors];
    },
]);
$server->on('WorkerStart', function ($server, $id) {
    [$starts] = Thread::getArguments();
    $starts[$id]->add();
});
$server->on('WorkerStop', function ($server, $id) {
    [, $stops, , $releaseFirst, $releaseSecond, , $stopping] = Thread::getArguments();
    if ($stops[$id]->add() === 1 && $id < 2) {
        $release = $id === 0 ? $releaseFirst : $releaseSecond;
        while (!$release->get() && !$stopping->get()) {
            usleep(1000);
        }
    }
});
$server->on('ManagerStart', function ($server) {
    [$starts, $stops, $userStarts, $releaseFirst, $releaseSecond, $releaseUser, , $after, $errors] = Thread::getArguments();
    $phase = 0;
    $ticks = 0;
    Timer::tick(5, function ($timerId) use (
        $server,
        $starts,
        $stops,
        $userStarts,
        $releaseFirst,
        $releaseSecond,
        $releaseUser,
        $after,
        $errors,
        &$phase,
        &$ticks
    ) {
        if ($phase === 0 && $starts[0]->get() && $starts[1]->get() && $starts[2]->get() && $userStarts->get()) {
            Assert::true($server->reload());
            $phase = 1;
        } elseif ($phase === 1 && $stops[0]->get()) {
            // Neither this unrelated user exit nor worker 2's independent stop may advance worker 1.
            $releaseUser->set(1);
            Assert::true($server->stop(2));
            $phase = 2;
        } elseif ($phase === 2 && $userStarts->get() >= 2 && $starts[2]->get() >= 2 && ++$ticks === 5) {
            if ($stops[1]->get() !== 0 || $after->get() !== 0) {
                $errors->add();
            }
            $releaseFirst->set(1);
            $ticks = 0;
            $phase = 3;
        } elseif ($phase === 3 && $stops[1]->get() && ++$ticks === 5) {
            if ($starts[2]->get() !== 2 || $stops[2]->get() !== 1 || $after->get() !== 0) {
                $errors->add();
            }
            $releaseSecond->set(1);
            $phase = 4;
        } elseif ($phase === 4 && $after->get() === 1 && $starts[0]->get() >= 2 && $starts[1]->get() >= 2) {
            Timer::clear($timerId);
            Assert::true($server->shutdown());
        }
    });
});
$server->on('BeforeReload', function () {
    static $calls = 0;
    Assert::same(++$calls, 1);
});
$server->on('AfterReload', function () {
    [, , , , $releaseSecond, , , $after, $errors] = Thread::getArguments();
    if (!$releaseSecond->get() || $after->add() !== 1) {
        $errors->add();
    }
});
$server->on('Start', function ($server) {
    Timer::after(8000, function () use ($server) {
        global $errors;
        $errors->add();
        $server->shutdown();
    });
});
$server->on('BeforeShutdown', function () {
    global $stopping;
    $stopping->set(1);
    Timer::clearAll();
});
$server->on('Shutdown', function () {
    global $starts, $after, $errors;
    Assert::same($errors->get(), 0);
    Assert::same($after->get(), 1);
    foreach ($starts as $count) {
        Assert::same($count->get(), 2);
    }
    echo "DONE\n";
});
$server->on('Receive', function () {});
$server->addProcess(new Swoole\Process(function () {
    [, , $userStarts, , , $releaseUser, $stopping] = Thread::getArguments();
    $initial = $userStarts->add() === 1;
    while (!$stopping->get() && !($initial && $releaseUser->get())) {
        usleep(1000);
    }
}));
$server->start();
?>
--EXPECT--
DONE
