--TEST--
swoole_pgsql_coro: lob
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\run(function () {
    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect(PGSQL_CONNECTION_STRING);
    Assert::true($connected, (string) $pgsql->error);

    $stmt = $pgsql->prepare("INSERT INTO weather(city, temp_lo, temp_hi, prcp, date) VALUES ($1, $2, $3, $4, $5)  RETURNING id");
    Assert::true(false !== $stmt, (string) $pgsql->error);

    $fp = fopen('php://memory', 'w+');
    Assert::true(!!$fp);
    fwrite($fp, 'Wuxi');
    rewind($fp);
    $result = $stmt->execute([$fp, $tempLo = rand(1000, 99999), 10, 0.75, '1993-11-23']);
    fclose($fp);
    Assert::true(false !== $result, (string) $pgsql->error);
    $id = $stmt->fetchAssoc()['id'] ?? null;
    Assert::greaterThanEq($id, 1);
    $stmt = $pgsql->prepare('select * from weather where id = $1');
    Assert::true(false !== $stmt, (string) $pgsql->error);
    $stmt->execute([$id]);
    var_dump($stmt->fetchAssoc());
});
?> 
--EXPECTF--
array(6) {
  ["id"]=>
  int(%d)
  ["city"]=>
  string(4) "Wuxi"
  ["temp_lo"]=>
  int(%d)
  ["temp_hi"]=>
  int(10)
  ["prcp"]=>
  float(0.75)
  ["date"]=>
  string(10) "1993-11-23"
}
