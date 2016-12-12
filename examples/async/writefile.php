<?php
use Swoole\Async;

Async::set(array('aio_mode' => SWOOLE_AIO_LINUX));
async::writefile(__DIR__.'/data2.txt', str_repeat('C', 4095)."\n", null, FILE_APPEND);
