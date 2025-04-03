--TEST--
swoole_process_pool: max wait time
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Constant;
use Swoole\Process\Pool;
use Swoole\Timer;

(function () {
    $atomic = new Atomic();
    $pool = new Pool(4, SWOOLE_IPC_NONE);
    $pool->set([
        Constant::OPTION_ENABLE_COROUTINE => true,
        Constant::OPTION_MAX_WAIT_TIME => 1,
    ]);

    $pool->on('workerStart', function (Pool $pool, int $workerId) use ($atomic): void {
        echo "workerStart: $workerId" . PHP_EOL;
        $atomic->wait(-1);
    });

    $pool->on('start', function () use ($pool): void {
        Timer::after(500, function () use ($pool): void {
            echo "shutdown\n";
            $pool->shutdown();
        });
        echo 'start' . PHP_EOL;
    });

    $pool->on('shutdown', function () use ($atomic): void {
        echo 'shutdown' . PHP_EOL;
    });

    $pool->start();
})();
?>
--EXPECTF--
start
workerStart: %d
workerStart: %d
workerStart: %d
workerStart: %d
shutdown
