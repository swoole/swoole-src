<?php
$q = new Swoole\RingQueue(10);

for ($i = 0; $i < 12; $i++)
{
    $ret = $q->push("hello_" . $i);
    var_dump($ret, $q->isFull(), $q->count());
}

for ($i = 0; $i < 12; $i++)
{
    $ret = $q->pop();
    var_dump($ret, $q->isEmpty(), $q->count());
}