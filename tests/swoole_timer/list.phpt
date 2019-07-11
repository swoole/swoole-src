--TEST--
swoole_timer: list
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$timers = [];
for ($c = MAX_CONCURRENCY; $c--;) {
    $timers[] = Swoole\Timer::after(mt_rand(1, 100), function () { });
}
$iterator = Swoole\Timer::list();
Assert::isInstanceOf($iterator, ArrayIterator::class);
Assert::same(iterator_to_array($iterator), $timers);
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
