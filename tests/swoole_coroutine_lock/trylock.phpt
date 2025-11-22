--TEST--
swoole_coroutine_lock: trylock
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Lock;
use Swoole\Coroutine\System;
use Swoole\Runtime;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

if (defined('SWOOLE_IOURING_SQPOLL')) {
    swoole_async_set([
        'iouring_workers' => 32,
        'iouring_entries' => 20000,
        'iouring_flag' => SWOOLE_IOURING_SQPOLL
    ]);
}

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
run(function () {
    $lock = new Lock(false);
    Assert::eq($lock->lock(LOCK_NB), true);
    go(function () use ($lock) {
        Assert::eq($lock->lock(LOCK_NB), false);
        $s = microtime(true);
        Assert::eq($lock->lock(), true);
        Assert::assert(microtime(true) - $s >= 0.05);
        echo "co2 end\n";
    });

    System::sleep(0.05);
    Assert::eq($lock->unlock(), true);
    echo "co1 end\n";
});
echo "DONE\n";
?>
--EXPECT--
co1 end
co2 end
DONE
