--TEST--
swoole_process_pool: enable coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pool = new Swoole\Process\Pool(1, SWOOLE_IPC_NONE, 0, false);
$pool->set(['enable_coroutine' => true]);

$counter = new Swoole\Atomic(0);

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) use ($counter) {
    if ($counter->get() <= 5) {
        Co::sleep(0.05);
        $counter->add(1);
        echo "hello world\n";
    }
});

$pool->on("workerStop", function ($pool, $data) use ($counter) {
    echo "worker stop\n";
    if ($counter->get() > 5) {
        $pool->shutdown();
    }
});

$pool->start();
?>
--EXPECT--
hello world
worker stop
hello world
worker stop
hello world
worker stop
hello world
worker stop
hello world
worker stop
hello world
worker stop
