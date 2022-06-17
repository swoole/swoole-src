--TEST--
swoole_pgsql_coro: prepare
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
    $result = $stmt->execute(['Beijing', rand(1000, 99999), 10, 0.75, '1993-11-23']);
    Assert::true(false !== $result, (string) $pgsql->error);
});
?> 
--EXPECT--
