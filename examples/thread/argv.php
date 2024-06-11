<?php

use Swoole\Thread;

$args = Thread::getArguments();

if (empty($args)) {
    var_dump($GLOBALS['argv']);
    $n = 2;
    while ($n--) {
        $thread = Thread::exec(__FILE__, 'thread-' . $n, $argc, $argv);
        $thread->join();
    }
} else {
    var_dump($args[0], $args[1], $args[2]);
    sleep(1);
}
