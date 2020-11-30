--TEST--
swoole_coroutine/async_callback: timer
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Timer;

$GLOBALS['count'] = 0;

Co\run(function () {
    Timer::tick(50, function ($timer) {
        $GLOBALS['count']++;
        if ($GLOBALS['count'] == 5) {
            Timer::clear($timer);
        }
        Co::sleep(0.5);
        echo "tick\n";
    });
});
?>
--EXPECT--
tick
tick
tick
tick
tick
