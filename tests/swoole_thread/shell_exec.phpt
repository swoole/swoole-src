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

$tm = new ThreadManager();

$tm->parentFunc = function () {
    Assert::true(Runtime::enableCoroutine(SWOOLE_HOOK_ALL));
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
    Co\run(function () {
        Assert::true(Runtime::enableCoroutine(SWOOLE_HOOK_ALL));
        shell_exec('ls /tmp');
        sleep(1);
        gethostbyname('www.baidu.com');
    });
    exit(0);
};

$tm->run();
?>
--EXPECT--
DONE
