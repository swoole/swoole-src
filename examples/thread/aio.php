<?php

use Swoole\Thread;
use Swoole\Thread\Queue;


$args = Thread::getArguments();
$c = 4;
$running = true;

if (empty($args)) {
    $threads = [];
    $atomic = new Swoole\Thread\Atomic();
    for ($i = 0; $i < $c; $i++) {
        $threads[] = new Thread(__FILE__, $i, $atomic);
    }
    for ($i = 0; $i < $c; $i++) {
        $threads[$i]->join();
    }
    var_dump($atomic->get());
    sleep(2);

    Co\run(function () use($atomic) {
        $n = 1024;
        while ($n--) {
            $atomic->add();
            $rs = \Swoole\Coroutine\System::readFile(__FILE__);
            var_dump(strlen($rs));
        }
    });
    var_dump($atomic->get());
} else {
    $atomic = $args[1];
    Co\run(function () use($atomic) {
        $n = 1024;
        while ($n--) {
            $atomic->add();
            $rs = \Swoole\Coroutine\System::readFile(__FILE__);
            var_dump(strlen($rs));
        }
    });
}
