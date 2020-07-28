--TEST--
swoole_redis_coro: redis client get options
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co::set([
    'connect_timeout' => 100,
    'socket_timeout' => 100,
]);
$redis = new Swoole\Coroutine\Redis();
var_dump($redis->getOptions());
$redis->setOptions([
    'connect_timeout' => 0.001,
    'timeout' => 0.001,
    'serialize' => true,
    'reconnect' => 3
]);
var_dump($redis->getOptions());
?>
--EXPECT--
array(6) {
  ["connect_timeout"]=>
  float(2)
  ["timeout"]=>
  float(100)
  ["serialize"]=>
  bool(false)
  ["reconnect"]=>
  int(1)
  ["password"]=>
  string(0) ""
  ["database"]=>
  int(0)
}
array(6) {
  ["connect_timeout"]=>
  float(0.001)
  ["timeout"]=>
  float(0.001)
  ["serialize"]=>
  bool(true)
  ["reconnect"]=>
  int(3)
  ["password"]=>
  string(0) ""
  ["database"]=>
  int(0)
}
