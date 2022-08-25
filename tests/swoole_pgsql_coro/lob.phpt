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
    $result = $stmt->execute([$fp, rand(1000, 99999), 10, 0.75, '1993-11-23']);
    fclose($fp);
    Assert::true(false !== $result, (string) $pgsql->error);
    $id = $stmt->fetchAssoc()['id'] ?? null;
    Assert::greaterThanEq($id, 1);
    $stmt2 = $pgsql->prepare('select * from weather where id = $1');
    Assert::true(false !== $stmt2, (string) $pgsql->error);
    $stmt2->execute([$id]);
    var_dump($stmt2->fetchAssoc());

    $result = $pgsql->query('begin');
    Assert::notEq($result, false, (string) $pgsql->error);
    $stmt = $pgsql->prepare("INSERT INTO oid(oid) VALUES ($1)  RETURNING id");
    Assert::true(false !== $stmt, (string) $pgsql->error);
    $oid = $pgsql->createLOB();
    Assert::integer($oid, (string) $pgsql->error);
    $lob = $pgsql->openLOB($oid, 'wb');
    Assert::notEq($lob, false, (string) $pgsql->error);
    fwrite($lob, 'Shanghai');
    $result = $stmt->execute([$lob]);
    Assert::true(false !== $result, (string) $pgsql->error);
    $result = $pgsql->query('commit');
    Assert::notEq($result, false, (string) $pgsql->error);

    $result = $pgsql->query('begin');
    Assert::notEq($result, false, (string) $pgsql->error);
    $id = $stmt->fetchAssoc()['id'] ?? null;
    Assert::greaterThanEq($id, 1);
    $stmt2 = $pgsql->prepare('select * from oid where id = $1');
    Assert::true(false !== $stmt2, (string) $pgsql->error);
    $stmt2->execute([$id]);
    $row = $stmt2->fetchRow(0, SW_PGSQL_ASSOC);
    $lob = $pgsql->openLOB($row['oid']);
    Assert::notEq($lob, false, (string) $pgsql->error);
    Assert::eq(fgets($lob), 'Shanghai');
    $result = $pgsql->query('commit');
    Assert::notEq($result, false, (string) $pgsql->error);

    $result = $pgsql->query('begin');
    Assert::notEq($result, false, (string) $pgsql->error);
    $oid = $pgsql->createLOB();
    Assert::integer($oid, (string) $pgsql->error);
    $lob = $pgsql->openLOB($oid, 'wb');
    Assert::notEq($lob, false, (string) $pgsql->error);
    var_dump($lob);
    fwrite($lob, 'test');
    $result = $pgsql->query('rollback');
    Assert::notEq($result, false, (string) $pgsql->error);
    var_dump($lob);

    $result = $pgsql->query('begin');
    Assert::notEq($result, false, (string) $pgsql->error);
    $oid = $pgsql->createLOB();
    Assert::integer($oid, (string) $pgsql->error);
    $lob = $pgsql->openLOB($oid, 'wb');
    Assert::notEq($lob, false, (string) $pgsql->error);
    var_dump($lob);
    fwrite($lob, 'test');
    $result = $pgsql->query('commit');
    Assert::notEq($result, false, (string) $pgsql->error);
    var_dump($lob);

    $result = $pgsql->query('begin');
    Assert::notEq($result, false, (string) $pgsql->error);
    $lob = $pgsql->openLOB($oid, 'wb');
    Assert::notEq($lob, false, (string) $pgsql->error);
    var_dump($lob);
    var_dump(fgets($lob));
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
resource(%d) of type (stream)
resource(%d) of type (Unknown)
resource(%d) of type (stream)
resource(%d) of type (Unknown)
resource(%d) of type (stream)
string(4) "test"
