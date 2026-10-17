--TEST--
swoole_timer: do not expire timers before their deadline
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Timer;

$running = true;
$defer = function () use (&$defer, &$running) {
    if ($running) {
        Event::defer($defer);
    }
};
Event::defer($defer);

while (hrtime(true) % 1_000_000 < 900_000) {
}
$start = hrtime(true);
Timer::tick(1, function (int $timerId) use (&$running, $start) {
    static $count = 0;
    $count++;
    Assert::greaterThanEq(hrtime(true) - $start, $count * 1_000_000);
    if ($count === 3) {
        $running = false;
        Timer::clear($timerId);
    }
});

Event::wait();
?>
--EXPECT--
