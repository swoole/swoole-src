<?php
$queue = new Swoole\MsgQueue(0x9501);
$msg = str_repeat('A', 8192);
$ret = $queue->push($msg);
var_dump($ret);
