<?php

$n = 1000;
$s = microtime(true);
$workers = [];

while($n--) {
    $workers[] = new Swoole\Process(function () {
        sleep(10000);
    }, false, false);
}

foreach($workers as $w) {
    $w->start();
}

echo microtime(true) - $s, "s\n";

foreach($workers as $w) {
    Swoole\Process::kill($w->pid, SIGKILL);
}