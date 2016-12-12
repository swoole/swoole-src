<?php
use Swoole\Async;

//Async::set(array('aio_mode' => SWOOLE_AIO_LINUX));
Async::writeFile(__DIR__.'/data2.txt', str_repeat('C', 1023)."\n", null, FILE_APPEND);
