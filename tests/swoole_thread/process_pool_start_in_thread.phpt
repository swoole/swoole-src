--TEST--
swoole_thread/process_pool: a pool cannot be started from another thread
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Exception;
use Swoole\Process\Pool;
use Swoole\Thread;

$arguments = Thread::getArguments();

if ($arguments === null) {
    $thread = new Thread(__FILE__, 'child');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    echo "DONE\n";
} else {
    // Swoole\Process\Pool is not serializable, so it has to be created inside the
    // thread. start() installs the pool's signal handlers process wide, which is
    // why it refuses to run anywhere but the main thread.

    try {
        $pool = new Pool(1);
        $pool->start();
        echo "MUST NOT REACH\n";
    } catch (Exception $e) {
        echo $e->getMessage(), "\n";
    }
    exit(0);
}
?>
--EXPECT--
This operation is only allowed in the main thread
DONE
