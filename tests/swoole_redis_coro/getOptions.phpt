--TEST--
swoole_redis_coro: redis client get options
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$redis = new Swoole\Coroutine\Redis();
$redis->setOptions([
    'connect_timeout' => 0.001,
    'timeout' => 0.001,
    'serialize' => true,
    'reconnect' => true
]);
var_dump($redis->getOptions());
?>
--EXPECT--
array(4) {
  ["connect_timeout"]=>
  float(0.001)
  ["timeout"]=>
  float(0.001)
  ["serialize"]=>
  bool(true)
  ["reconnect"]=>
  bool(true)
}
