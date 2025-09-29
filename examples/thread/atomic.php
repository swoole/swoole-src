<?php

use Swoole\Thread;
use Swoole\Thread\Atomic;
use Swoole\Thread\Atomic\Long;

$args = Thread::getArguments();
$c = 4;
$n = 128;

if (empty($args)) {
    $threads = [];
    $a1 = new Atomic;
    $a2 = new Long;
    for ($i = 0; $i < $c; $i++) {
        $threads[] = new Thread(__FILE__, $i, $a1, $a2);
    }
    for ($i = 0; $i < $c; $i++) {
        $threads[$i]->join();
    }
    var_dump($a1->get(), $a2->get());
} else {
    $a1 = $args[1];
    $a2 = $args[2];

    $a1->add(3);
    $a2->add(7);
}
