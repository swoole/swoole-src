<?php

$mq = new Swoole\MsgQueue(0x7000001);
for ($i = 0; $i < 1000; ++$i) {
    if (99 == $i % 100) {
        var_dump($mq->stats());
    } elseif (299 == $i % 300) {
        sleep(1);
    }
    $mq->push("hello $i");
}
