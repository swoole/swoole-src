--TEST--
swoole_server: reload from manager callbacks starts without another signal or manager timer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$starts = [new Swoole\Atomic(), new Swoole\Atomic()];
$initialPids = [new Swoole\Atomic(), new Swoole\Atomic()];
$currentPids = [new Swoole\Atomic(), new Swoole\Atomic()];
$after = new Swoole\Atomic();
$errors = new Swoole\Atomic();
$timedOut = new Swoole\Atomic();
$masterPid = getmypid();

function waitForStarts(array $starts, array $expected): bool
{
    $deadline = microtime(true) + 3;
    do {
        if ($starts[0]->get() >= $expected[0] && $starts[1]->get() >= $expected[1]) {
            return true;
        }
        usleep(1000);
    } while (microtime(true) < $deadline);
    return false;
}

$server = new Swoole\Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS);
$server->set([
    'worker_num' => 1,
    'task_worker_num' => 1,
    'max_wait_time' => 0,
    'enable_coroutine' => false,
    'log_file' => '/dev/null',
]);
$server->on('Receive', function () {});
$server->on('Task', function () {});
$server->on('WorkerStart', function ($server, $id) use ($starts, $initialPids, $currentPids, $errors, $masterPid) {
    if ($server->master_pid !== $masterPid) {
        $errors->add();
    }
    $currentPids[$id]->set(getmypid());
    if ($starts[$id]->add() === 1) {
        $initialPids[$id]->set(getmypid());
    }
});
$server->on('ManagerStart', function ($server) use ($starts, $errors) {
    if (!waitForStarts($starts, [1, 1]) || !$server->reload(true)) {
        $errors->add();
        $server->shutdown();
    }
});
$server->on('AfterReload', function ($server) use ($starts, $after, $errors) {
    if ($after->add() === 1 && (!waitForStarts($starts, [1, 2]) || !$server->reload())) {
        $errors->add();
        $server->shutdown();
    }
});
$server->on('Start', function ($server) use ($starts, $after, $timedOut) {
    $deadline = microtime(true) + 5;
    Swoole\Timer::tick(10, function ($id) use ($server, $starts, $after, $timedOut, $deadline) {
        if ($after->get() === 2 && $starts[0]->get() === 2 && $starts[1]->get() === 3) {
            Swoole\Timer::clear($id);
            $server->shutdown();
        } elseif (microtime(true) >= $deadline) {
            $timedOut->set(1);
            Swoole\Timer::clear($id);
            $server->shutdown();
        }
    });
});
$server->start();
Assert::same($timedOut->get(), 0);
Assert::same($errors->get(), 0);
Assert::same($after->get(), 2);
foreach ([2, 3] as $id => $expected) {
    Assert::same($starts[$id]->get(), $expected);
    Assert::greaterThan($initialPids[$id]->get(), 0);
    Assert::notSame($currentPids[$id]->get(), $initialPids[$id]->get());
}
echo "DONE\n";
?>
--EXPECT--
DONE
