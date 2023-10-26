--TEST--
swoole_pgsql_coro: fetch
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\run(function () {
    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect(PGSQL_CONNECTION_STRING);
    Assert::true($connected, (string) $pgsql->error);

    $stmt = $pgsql->query('SELECT * FROM weather;');
    Assert::true(false !== $stmt, (string) $pgsql->error);

    var_dump($stmt->fetchObject(0), $stmt->fetchObject(1));
    var_dump($stmt->fetchAssoc(0), $stmt->fetchAssoc(1));
    var_dump($stmt->fetchArray(0), $stmt->fetchArray(1));
    var_dump($stmt->fetchRow(0), $stmt->fetchRow(1));
});
?>
--EXPECTF--
object(stdClass)#%d (6) {
  ["id"]=>
  int(1)
  ["city"]=>
  string(13) "San Francisco"
  ["temp_lo"]=>
  int(46)
  ["temp_hi"]=>
  int(50)
  ["prcp"]=>
  float(0.25)
  ["date"]=>
  string(10) "1994-11-27"
}
object(stdClass)#%d (6) {
  ["id"]=>
  int(2)
  ["city"]=>
  string(5) "Test2"
  ["temp_lo"]=>
  int(11)
  ["temp_hi"]=>
  int(22)
  ["prcp"]=>
  float(0.3)
  ["date"]=>
  string(10) "1994-11-28"
}
array(6) {
  ["id"]=>
  int(1)
  ["city"]=>
  string(13) "San Francisco"
  ["temp_lo"]=>
  int(46)
  ["temp_hi"]=>
  int(50)
  ["prcp"]=>
  float(0.25)
  ["date"]=>
  string(10) "1994-11-27"
}
array(6) {
  ["id"]=>
  int(2)
  ["city"]=>
  string(5) "Test2"
  ["temp_lo"]=>
  int(11)
  ["temp_hi"]=>
  int(22)
  ["prcp"]=>
  float(0.3)
  ["date"]=>
  string(10) "1994-11-28"
}
array(12) {
  [0]=>
  int(1)
  ["id"]=>
  int(1)
  [1]=>
  string(13) "San Francisco"
  ["city"]=>
  string(13) "San Francisco"
  [2]=>
  int(46)
  ["temp_lo"]=>
  int(46)
  [3]=>
  int(50)
  ["temp_hi"]=>
  int(50)
  [4]=>
  float(0.25)
  ["prcp"]=>
  float(0.25)
  [5]=>
  string(10) "1994-11-27"
  ["date"]=>
  string(10) "1994-11-27"
}
array(12) {
  [0]=>
  int(2)
  ["id"]=>
  int(2)
  [1]=>
  string(5) "Test2"
  ["city"]=>
  string(5) "Test2"
  [2]=>
  int(11)
  ["temp_lo"]=>
  int(11)
  [3]=>
  int(22)
  ["temp_hi"]=>
  int(22)
  [4]=>
  float(0.3)
  ["prcp"]=>
  float(0.3)
  [5]=>
  string(10) "1994-11-28"
  ["date"]=>
  string(10) "1994-11-28"
}
array(6) {
  [0]=>
  int(1)
  [1]=>
  string(13) "San Francisco"
  [2]=>
  int(46)
  [3]=>
  int(50)
  [4]=>
  float(0.25)
  [5]=>
  string(10) "1994-11-27"
}
array(6) {
  [0]=>
  int(2)
  [1]=>
  string(5) "Test2"
  [2]=>
  int(11)
  [3]=>
  int(22)
  [4]=>
  float(0.3)
  [5]=>
  string(10) "1994-11-28"
}
