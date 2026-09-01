--TEST--
swoole_thread: fatal error 3
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use SwooleTest\ThreadManager;

$tm = new ThreadManager();

$tm->parentFunc = function () {
    register_shutdown_function(function () {
        echo "shutdown\n";
    });
    Assert::eq(Thread::getInfo()['thread_num'], 1);
    $thread = new Thread(__FILE__, 'child');
    usleep(100000);
    echo "main thread\n";
    Assert::eq(Thread::getInfo()['thread_num'], 2);
    $thread->detach();
};

$tm->childFunc = function () {
    echo "child thread\n";
    sleep(1000);
    exit(0);
};

$tm->run();
?>
--EXPECTF--
child thread
main thread
shutdown
[%s]	WARNING	php_swoole_thread_rshutdown(): Fatal Error: 2 active threads are running, cannot exit safely.
