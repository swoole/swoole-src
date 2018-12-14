<?php
$mq = new Swoole\MsgQueue(0x7000001);
for ($i = 0; $i < 1000; $i++)
{
    if ($i % 100 == 99)
    {
        var_dump($mq->stats());
    }
    elseif ($i % 300 == 299)
    {
        sleep(1);
    }
    $mq->push("hello $i");
}
