--TEST--
swoole_coroutine: cid map max num
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
co::set([
    'max_coroutine' => SWOOLE_DEFAULT_MAX_CORO_NUM
]);
for ($c = SWOOLE_DEFAULT_MAX_CORO_NUM + 1; $c--;) {
    $ret = go(function () {
        co::sleep(0.001);
    });
}
var_dump(co::stats());
?>
--EXPECTF--
Warning: go(): exceed max number of coroutine 3000. in %s/tests/swoole_coroutine/max_num.php on line 9
array(3) {
  ["stack_size"]=>
  int(8192)
  ["coroutine_num"]=>
  int(3000)
  ["coroutine_peak_num"]=>
  int(3000)
}
