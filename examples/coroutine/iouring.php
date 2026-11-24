<?php
// On io_uring builds, System::sleep() is served by the kernel ring instead
// of a timer. Run: php examples/coroutine/iouring.php
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

run(function () {
    echo 'io_uring available: ', defined('SWOOLE_IOURING_DEFAULT') ? 'yes' : 'no', PHP_EOL;
    System::sleep(0.01);
    echo 'sleep() completed' . PHP_EOL;
});
