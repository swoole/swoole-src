--TEST--
swoole_timer: list
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$timers = [];
for ($c = 1000; $c--;) {
    $msec = mt_rand(100, 500);
    $timers[Swoole\Timer::after($msec, function () { })] = $msec;
}
foreach (Swoole\Timer::list() as $timer_id) {
    $info = Swoole\Timer::info($timer_id);
    time_approximate($timers[$timer_id], $info['exec_msec']);
    Assert::same($info['interval'], 0);
    Assert::same($info['round'], 0);
    Assert::false($info['removed']);
}
Swoole\Timer::tick(1, function (int $timer_id) {
    // tick
    $info = Swoole\Timer::info($timer_id);
    Assert::greaterThan($info['interval'], 0);
    Assert::same($info['round'], 0);
    Assert::false($info['removed']);
    // remove
    Swoole\Timer::clear($timer_id);
    $info = Swoole\Timer::info($timer_id);
    Assert::true($info['removed']);
    // after
    $info = Swoole\Timer::info(Swoole\Timer::after(1, function () { }));
    Assert::greaterThan($info['exec_msec'], 0);
    Assert::same($info['interval'], 0);
    Assert::same($info['round'], 1); // next round
    Assert::false($info['removed']);
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
