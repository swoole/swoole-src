--TEST--
swoole_thread: name
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$tm = new \SwooleTest\ThreadManager();

Assert::eq(Thread::API_NAME, 'POSIX Threads');

$tm->parentFunc = function () {
    $thread = new Thread(__FILE__, 'child');
    Thread::setName('master thread');
    Assert::eq(get_thread_name(), 'master thread');
    $thread->join();
};

$tm->childFunc = function () {
    Thread::setName('child thread');
    Assert::eq(get_thread_name(), 'child thread');
};

$tm->run();
?>
--EXPECTF--
