--TEST--
swoole_redis_coro: hGetAll hmGet zRange zRevRange zRangeByScore zRevRangeByScore
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function() {
    $redis = new Swoole\Coroutine\Redis();
    $redis->setOptions(['compatibility_mode' => true]);
    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT);
    
    $redis->delete('hkey');
    $redis->hSet('hkey', false, 'val0');
    $redis->hSet('hkey', "field", 'val1');
    $redis->hSet('hkey', 5, 'val5');

    $redis->delete('zkey');
    $redis->zAdd('zkey', "field", 'val0');
    $redis->zAdd('zkey', true, 'val1');
    $redis->zAdd('zkey', 5, 'val5');
    
    echo "-----get---\n";
    var_dump($redis->get('novalue'));
    echo "-----zRank---\n";
    var_dump($redis->zRank('novalue', 1));
    echo "-----hGetAll---\n";
    var_dump($redis->hGetAll('hkey'));
    echo "-----hmGet---\n";
    var_dump($redis->hmGet('hkey', [3, 5]));
    echo "-----zRange---\n";
    var_dump($redis->zRange('zkey', 0, 99, true));
    echo "-----zRevRange---\n";
    var_dump($redis->zRevRange('zkey', 0, 99, true));
    echo "-----zRangeByScore---\n";
    var_dump($redis->zRangeByScore('zkey', 0, 99, ['withscores' => true]));
    echo "-----zRevRangeByScore---\n";
    var_dump($redis->zRevRangeByScore('zkey', 99, 0, ['withscores' => true]));
});
?>
--EXPECT--
-----get---
bool(false)
-----zRank---
bool(false)
-----hGetAll---
array(3) {
  [""]=>
  string(4) "val0"
  ["field"]=>
  string(4) "val1"
  [5]=>
  string(4) "val5"
}
-----hmGet---
array(2) {
  [3]=>
  bool(false)
  [5]=>
  string(4) "val5"
}
-----zRange---
array(3) {
  ["val0"]=>
  float(0)
  ["val1"]=>
  float(1)
  ["val5"]=>
  float(5)
}
-----zRevRange---
array(3) {
  ["val5"]=>
  float(5)
  ["val1"]=>
  float(1)
  ["val0"]=>
  float(0)
}
-----zRangeByScore---
array(3) {
  ["val0"]=>
  float(0)
  ["val1"]=>
  float(1)
  ["val5"]=>
  float(5)
}
-----zRevRangeByScore---
array(3) {
  ["val5"]=>
  float(5)
  ["val1"]=>
  float(1)
  ["val0"]=>
  float(0)
}
