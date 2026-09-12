--TEST--
swoole_thread: stdio close
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

$tm->parentFunc = function () {
    $count = count(scandir('/proc/self/fd'));
    $thread = new Thread(__FILE__, 'child');
    $thread->join();
    Assert::eq(count(scandir('/proc/self/fd')), $count);
    echo "DONE\n";
};

$tm->childFunc = function () {
};

$tm->run();
?>
--EXPECT--
DONE
