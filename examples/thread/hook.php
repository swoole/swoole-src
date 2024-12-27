<?php

use Swoole\Thread;
use Swoole\Thread\Lock;

$args = Thread::getArguments();

if (empty($args)) {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
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
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
    sleep(1);
    Swoole\Runtime::enableCoroutine(0);
    exit(234);
}
