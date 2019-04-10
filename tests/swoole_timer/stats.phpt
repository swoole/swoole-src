--TEST--
swoole_timer: list
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$s = microtime(true);
var_dump(Swoole\Timer::stats());
for ($c = 1000; $c--;) {
    Swoole\Timer::after(mt_rand(1, 1000), function () { });
}
var_dump(Swoole\Timer::stats());
foreach (Swoole\Timer::list() as $timer_id) {
    Assert::true(Swoole\Timer::clear($timer_id));
}
Swoole\Timer::after(100, function () {
    var_dump(Swoole\Timer::stats());
});
Swoole\Event::wait();
time_approximate(0.1, microtime(true) - $s);
?>
--EXPECTF--
array(3) {
  ["initialized"]=>
  bool(false)
  ["num"]=>
  int(0)
  ["round"]=>
  int(0)
}
array(3) {
  ["initialized"]=>
  bool(true)
  ["num"]=>
  int(1000)
  ["round"]=>
  int(0)
}
array(3) {
  ["initialized"]=>
  bool(true)
  ["num"]=>
  int(1)
  ["round"]=>
  int(1)
}
