--TEST--
swoole_thread: thread status
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$t1 = new Thread(TESTS_API_PATH . '/swoole_thread/sleep.php');
usleep(10);
Assert::true($t1->joinable());
Assert::true($t1->isAlive());
Assert::true($t1->join());
Assert::false($t1->joinable());
Assert::false($t1->isAlive());

$t2 = new Thread(TESTS_API_PATH . '/swoole_thread/sleep.php');
$t2->detach();
usleep(10);
Assert::false($t2->joinable());
Assert::true($t2->isAlive());
while (Thread::getInfo()['thread_num'] > 1) {
    usleep(10);
}
Assert::false($t2->isAlive());
?>
--EXPECT--
