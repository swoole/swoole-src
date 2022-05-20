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

    $result = $pgsql->query("INSERT INTO weather(city, temp_lo, temp_hi, prcp, date) VALUES ('Shanghai', 88, 10, 0.75,'1993-11-27')  RETURNING id");
    Assert::true(false !== $result, (string) $pgsql->error);
    Assert::eq($pgsql->numRows($result), 1);
    Assert::greaterThan($pgsql->fetchAssoc($result)['id'], 1);
});
?>
--EXPECT--
