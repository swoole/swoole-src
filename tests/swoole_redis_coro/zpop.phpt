--TEST--
swoole_redis_coro: zPopMin zPopMax bzPopMin bzPopMax
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_not_redis5();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function() {
    $redis = new Swoole\Coroutine\Redis();
    $redis->setOptions(['compatibility_mode' => true]);
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    
    $redis->delete('zkeyA');
    $redis->zAdd('zkeyA', 1, 'val1');
    $redis->zAdd('zkeyA', 2, 'val2');
    $redis->zAdd('zkeyA', 3, 'val3');
    $redis->zAdd('zkeyA', 4, 'val4');
    $redis->zAdd('zkeyA', 5, 'val5');
    
    $redis->delete('zkeyB');
    $redis->zAdd('zkeyB', 1, 'val1');
    $redis->zAdd('zkeyB', 2, 'val2');
    $redis->zAdd('zkeyB', 3, 'val3');
    $redis->zAdd('zkeyB', 4, 'val4');
    $redis->zAdd('zkeyB', 5, 'val5');

    echo "-----ZPOPMIN---\n";
    var_dump($redis->ZPOPMIN('zkeyA'));
    echo "-----ZPOPMAX---\n";
    var_dump($redis->ZPOPMAX('zkeyB'));
    echo "-----BZPOPMIN---\n";
    var_dump($redis->BZPOPMIN(['zkeyB','zkeyA'], 2));
    echo "-----BZPOPMAX---\n";
    var_dump($redis->BZPOPMAX('zkeyB','zkeyA', 2));
    echo "-----BZPOPMIN no data---\n";
    var_dump($redis->BZPOPMAX('zkeyC','zkeyD', 2));
});
--EXPECT--
-----ZPOPMIN---
array(2) {
  [0]=>
  string(4) "val1"
  [1]=>
  string(1) "1"
}
-----ZPOPMAX---
array(2) {
  [0]=>
  string(4) "val5"
  [1]=>
  string(1) "5"
}
-----BZPOPMIN---
array(3) {
  [0]=>
  string(5) "zkeyB"
  [1]=>
  string(4) "val1"
  [2]=>
  string(1) "1"
}
-----BZPOPMAX---
array(3) {
  [0]=>
  string(5) "zkeyB"
  [1]=>
  string(4) "val4"
  [2]=>
  string(1) "4"
}
-----BZPOPMIN no data---
NULL