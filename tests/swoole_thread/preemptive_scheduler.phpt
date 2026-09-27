--TEST--
swoole_thread: preemptive coroutine scheduler
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

co::set(['enable_preemptive_scheduler' => true]);

$running = true;

go(function () use (&$running) {
    echo "coro 1 start\n";
    while ($running) {
    }
    echo "coro 1 stop\n";
});

go(function () use (&$running) {
    echo "coro 2 stop\n";
    $running = false;
});

echo "end\n";
Swoole\Event::wait();
?>
--EXPECT--
coro 1 start
coro 2 stop
end
coro 1 stop
