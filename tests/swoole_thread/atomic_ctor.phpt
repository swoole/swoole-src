--TEST--
swoole_thread: atomic ctor
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


$tm = new \SwooleTest\ThreadManager();

$tm->parentFunc = function () {
    $lock = new Lock;
    $lock->lock();
    $num1 = random_int(1, 1 << 31);
    $num2 = random_int(1 << 31, PHP_INT_MAX);
    $atomic1 = new Swoole\Thread\Atomic($num1);
    $atomic2 = new Swoole\Thread\Atomic\Long($num2);
    $thread = new Thread(__FILE__, $lock, $atomic1, $atomic2, $num1, $num2);
    $lock->lock();
    echo "main thread\n";
    $thread->join();
};

$tm->childFunc = function ($lock, $atomic1, $atomic2, $num1, $num2) {
    echo "child thread\n";
    usleep(200_000);
    $lock->unlock();
    Assert::eq($atomic1->get(), $num1);
    Assert::eq($atomic2->get(), $num2);
    exit(0);
};

$tm->run();
?>
--EXPECTF--
child thread
main thread
