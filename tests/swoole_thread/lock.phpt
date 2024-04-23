--TEST--
swoole_thread: lock
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Lock;

$args = Thread::getArguments();

if (empty($args)) {
    global $argv;
    $lock = new Lock;
    $lock->lock();
    $thread = Thread::exec(__FILE__, $argv, $lock);
    $lock->lock();
    echo "main thread\n";
    $thread->join();
} else {
    echo "child thread\n";
    $lock = $args[1];
    usleep(200_000);
    $lock->unlock();
    exit(0);
}
?>
--EXPECTF--
child thread
main thread

