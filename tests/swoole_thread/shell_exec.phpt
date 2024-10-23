--TEST--
swoole_thread: lock
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Lock;
use Swoole\Runtime;
use SwooleTest\ThreadManager;

const CODE = 234;

$tm = new ThreadManager();

$tm->parentFunc = function () {
    Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    $lock = new Lock;
    $lock->lock();
    $thread = new Thread(__FILE__, $lock);
    $lock->unlock();
    $thread->join();
    Assert::eq($thread->getExitStatus(), 0);
    echo 'DONE' . PHP_EOL;
};

$tm->childFunc = function ($lock) {
    $lock->lock();
    usleep(100_000);
//    shell_exec('ls /tmp');
    Co\run(function (){
        shell_exec('ls /tmp');
    });
    exit(0);
};

$tm->run();
?>
--EXPECT--
DONE
