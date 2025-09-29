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
Assert::false($t1->isAlive());
$t1->detach();
Thread::yield();
usleep(10);
Assert::true($t1->isAlive());
while (Thread::activeCount() > 1) {
    usleep(10);
}
Assert::false($t1->isAlive());
?>
--EXPECT--
