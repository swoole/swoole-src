--TEST--
swoole_timer: overflowing deadlines are rejected without affecting existing timers
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('64-bit integers are required', PHP_INT_SIZE < 8);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine::set(['log_file' => '/dev/null']);
$called = 0;
Swoole\Coroutine\run(static function () use (&$called) {
    // Let the timer's relative clock advance before adding an interval equal to INT64_MAX.
    Swoole\Coroutine::sleep(0.002);
    $id = Swoole\Timer::after(10, static function () use (&$called) { $called++; });
    $before = Swoole\Timer::info($id);
    $count = Swoole\Timer::stats()['num'];
    Assert::false(@Swoole\Timer::after(PHP_INT_MAX, static function () { Assert::true(false); }));
    Assert::false(@Swoole\Timer::tick(PHP_INT_MAX, static function () { Assert::true(false); }));
    Assert::same(Swoole\Timer::stats()['num'], $count);
    Assert::same(Swoole\Timer::info($id), $before);
});
Assert::same($called, 1);
echo "DONE\n";
?>
--EXPECT--
DONE
