<?php

use Swoole\Thread;
use Swoole\Lock;

$args = Thread::getArguments();

if (empty($args)) {
    $lock = new Lock;
    $lock->lock();
    $thread = Thread::exec(__FILE__, $lock);
    $lock->lock();
    echo "main thread\n";
    $thread->join();
} else {
    $lock = $args[0];
    sleep(1);
    $lock->unlock();
}
