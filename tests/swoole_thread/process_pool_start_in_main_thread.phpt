--TEST--
swoole_thread/process_pool: the main thread may start a pool once other threads have exited
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_class_not_exist(Swoole\Process\Pool::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process\Pool;
use Swoole\Thread;

$arguments = Thread::getArguments();

if ($arguments === null) {
    $pool = new Pool(1);
    $pool->on('workerStart', function (Pool $pool, int $workerId) {
        $pool->shutdown();
    });

    $thread = new Thread(__FILE__, 'child');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    Assert::same(Thread::activeCount(), 1);

    $pool->start();
    echo "DONE\n";
} else {

}
?>
--EXPECT--
DONE
