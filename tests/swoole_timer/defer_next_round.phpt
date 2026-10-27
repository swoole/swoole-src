--TEST--
swoole_timer: timers created by deferred callbacks run after the next poll
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Timer;

foreach ([false, true] as $existingTimer) {
    $iteration = 0;
    Event::cycle(function () use (&$iteration) {
        ++$iteration;
    }, true);

    $keepAlive = $existingTimer ? Timer::after(60000, function () {}) : null;
    Event::defer(function () use (&$iteration, $keepAlive) {
        $created = $iteration;
        Timer::after(1, function () use (&$iteration, $created, $keepAlive) {
            echo $keepAlive === null ? 'first timer: ' : 'existing timer: ';
            echo $iteration - $created, " poll\n";
            if ($keepAlive !== null) {
                Timer::clear($keepAlive);
            }
            Event::cycle(null, true);
        });
        // Make the timer due before polling again, without relying on a timing assertion.
        usleep(5000);
    });
    Event::wait();
}
?>
--EXPECT--
first timer: 1 poll
existing timer: 1 poll
