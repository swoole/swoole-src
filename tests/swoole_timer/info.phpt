--TEST--
swoole_timer: list
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$timers = [];
for ($c = MAX_REQUESTS; $c--;) {
    $msec = mt_rand(1, 100);
    $timers[Swoole\Timer::after($msec, function () { })] = $msec;
}
foreach (Swoole\Timer::list() as $timer_id) {
    $info = Swoole\Timer::info($timer_id);
    Assert::eq($info['id'], $timer_id);
    time_approximate($timers[$timer_id], $info['exec_msec']);
    Assert::eq($info['round'], 0);
    Assert::false($info['removed']);
}
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
