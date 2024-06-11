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

$tm->parentFunc = function () {
    $thread = new Thread(__FILE__, 'child');
    $info = Thread::getTsrmInfo();
    Assert::true($info['is_main_thread']);
    Assert::eq($info['api_name'], 'POSIX Threads');
    $thread->join();
};

$tm->childFunc = function () {
    $info = Thread::getTsrmInfo();
    Assert::false($info['is_main_thread']);
    Assert::eq($info['api_name'], 'POSIX Threads');
};

$tm->run();
?>
--EXPECTF--
