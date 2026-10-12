--TEST--
swoole_thread/server: CPU affinity applies to worker threads without changing the master
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
skip_if_no_process_affinity();
skip('requires two CPUs', count(Swoole\Process::getAffinity()) < 2);
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Process;
use Swoole\Server;
use Swoole\Thread;
use Swoole\Timer;

$isMain = Thread::getArguments() === null;
if ($isMain) {
    $original = Process::getAffinity();
    $cpus = [$original[0], $original[count($original) - 1]];
    Assert::true(Process::setAffinity($cpus));
}

$server = new Server('127.0.0.1', 0, SWOOLE_THREAD);
if ($isMain) {
    $queue = new Thread\Queue();
    $ready = new Thread\Atomic();
    $server->set([
        'worker_num' => 2,
        'task_worker_num' => 2,
        'open_cpu_affinity' => true,
        'cpu_affinity_ignore' => [$cpus[0]],
        'log_file' => '/dev/null',
        'init_arguments' => function () use ($cpus, $queue, $ready) {
            return [$cpus, $queue, $ready];
        },
    ]);
}
$server->on('workerStart', function (Server $server, int $workerId) {
    [$cpus, $queue, $ready] = Thread::getArguments();
    $queue->push(json_encode([$workerId, Thread::getAffinity()]));
    $ready->add();
    if ($workerId === 0) {
        Timer::tick(10, function (int $timerId) use ($server, $ready) {
            if ($ready->get() === 4) {
                Timer::clear($timerId);
                $server->shutdown();
            }
        });
        Timer::after(5000, function () use ($server) {
            $server->shutdown();
        });
    }
});
$server->on('receive', function () {});
$server->on('task', function () {});
$server->on('finish', function () {});
Assert::true($server->start());

if ($isMain) {
    Assert::same($ready->get(), 4);
    $workerIds = [];
    for ($i = 0; $i < 4; $i++) {
        [$workerId, $actual] = json_decode($queue->pop(1), true);
        $workerIds[] = $workerId;
        Assert::same($actual, [$cpus[1]]);
    }
    sort($workerIds);
    Assert::same($workerIds, [0, 1, 2, 3]);
    Assert::same(Process::getAffinity(), $cpus);
    Assert::true(Process::setAffinity($original));
    echo "DONE\n";
}
?>
--EXPECT--
DONE
