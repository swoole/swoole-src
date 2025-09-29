<?php

use Swoole\Thread;
use Swoole\Thread\Lock;

$args = Thread::getArguments();

if (empty($args)) {
    $lock = new Lock;
    $lock->lock();
    $thread = new Thread(__FILE__, $lock);
    echo "main thread\n";
    $lock->unlock();
    $thread->join();
    var_dump($thread->getExitStatus());
} else {
    $lock = $args[0];
    $lock->lock();
    sleep(1);
    exit(234);
}
