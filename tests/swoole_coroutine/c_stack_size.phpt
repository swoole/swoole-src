--TEST--
swoole_coroutine: c_stack_size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
echo "default 2M\n";
var_dump(co::stats());
co::set(['c_stack_size' => 1024 * 1024]);
for ($n = MAX_REQUESTS; $n--;) {
    go(function () { co::sleep(0.001); });
}
echo "1M\n";
var_dump(co::stats());
co::set(['c_stack_size' => 1]); // will be aligned
for ($n = MAX_REQUESTS; $n--;) {
    go(function () { co::sleep(0.001); });
}
echo "4K\n";
var_dump(co::stats());
co::set(['c_stack_size' => 1024 * 1024 * 1024]); // will be limit
for ($n = MAX_REQUESTS; $n--;) {
    go(function () { co::sleep(0.001); });
}
echo "16M\n";
var_dump(co::stats());
co::set(['c_stack_size' => -1]); // will be limit
for ($n = MAX_REQUESTS; $n--;) {
    go(function () { co::sleep(0.001); });
}
echo "16M\n";
var_dump(co::stats());
?>
--EXPECTF--

default 2M
array(3) {
  ["c_stack_size"]=>
  int(2097152)
  ["coroutine_num"]=>
  int(0)
  ["coroutine_peak_num"]=>
  int(0)
}
1M
array(3) {
  ["c_stack_size"]=>
  int(1048576)
  ["coroutine_num"]=>
  int(100)
  ["coroutine_peak_num"]=>
  int(100)
}
4K
array(3) {
  ["c_stack_size"]=>
  int(4096)
  ["coroutine_num"]=>
  int(200)
  ["coroutine_peak_num"]=>
  int(200)
}
16M
array(3) {
  ["c_stack_size"]=>
  int(16777216)
  ["coroutine_num"]=>
  int(300)
  ["coroutine_peak_num"]=>
  int(300)
}
16M
array(3) {
  ["c_stack_size"]=>
  int(16777216)
  ["coroutine_num"]=>
  int(400)
  ["coroutine_peak_num"]=>
  int(400)
}
