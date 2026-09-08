--TEST--
swoole_thread: info
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$tm = new \SwooleTest\ThreadManager();

Assert::eq(Thread::API_NAME, PHP_OS_FAMILY === 'Windows' ? 'Windows Threads' : 'POSIX Threads');

$tm->parentFunc = function () {
    $thread = new Thread(__FILE__, 'child');
    $info = Thread::getInfo();
    Assert::true($info['is_main_thread']);
    $thread->join();
};

$tm->childFunc = function () {
    $info = Thread::getInfo();
    Assert::false($info['is_main_thread']);
};

$tm->run();
?>
--EXPECTF--
