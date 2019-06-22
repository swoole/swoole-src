<?php
$lock = new Swoole\Lock();
$c = 2;

while ($c--) {
    go(function () use ($lock) {
        $lock->lock();
        Co::sleep(1);
        $lock->unlock();
    });
}
