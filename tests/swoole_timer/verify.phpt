--TEST--
swoole_timer: verify timer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
for ($c = MAX_CONCURRENCY; $c--;) {
    go(function () {
        $seconds = ms_random(0.1, 0.5);
        $start = microtime(true);
        Co::sleep($seconds);
        time_approximate($seconds, microtime(true) - $start, 0.25);
    });
}
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
