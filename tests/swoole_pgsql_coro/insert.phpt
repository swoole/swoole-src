--TEST--
swoole_pgsql_coro: insert
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\run(function () {
    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect(PGSQL_CONNECTION_STRING);
    Assert::true($connected, (string) $pgsql->error);

    $stmt = $pgsql->query("INSERT INTO weather(city, temp_lo, temp_hi, prcp, date) VALUES ('Shanghai', 88, 10, 0.75,'1993-11-27')  RETURNING id");
    Assert::true(false !== $stmt, (string) $pgsql->error);
    Assert::eq($stmt->numRows(), 1);
    Assert::greaterThan($stmt->fetchAssoc()['id'], 1);
});
?>
--EXPECT--
