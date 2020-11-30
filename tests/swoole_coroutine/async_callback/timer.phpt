--TEST--
swoole_coroutine/async_callback: call
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Timer;
use Swoole\Event;

$GLOBALS['count'] = 0;

Timer::tick(50, function ($timer) {
    $GLOBALS['count']++;
    if ($GLOBALS['count'] == 5) {
        Timer::clear($timer);
    }
    Co::sleep(0.5);
    echo "tick\n";
});

Event::Wait();
?>
--EXPECT--
tick
tick
tick
tick
tick
