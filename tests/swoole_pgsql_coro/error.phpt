--TEST--
swoole_pgsql_coro: error
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\run(function () {
    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect(PGSQL_CONNECTION_STRING);
    Assert::true($connected, (string) $pgsql->error);

    $stmt = $pgsql->query('SELECT * FROM not_exists;');
    Assert::false($stmt, (string) $pgsql->error);

    $stmt = $pgsql->prepare('SELECT * FROM not_exists;');
    Assert::false($stmt, (string) $pgsql->error);

    $stmt = $pgsql->prepare("INSERT INTO weather(city, temp_lo, temp_hi, prcp, date) VALUES ($1, $2, $3, $4, $5)  RETURNING id");
    Assert::true(false !== $stmt, (string) $pgsql->error);

    $result = $stmt->affectedRows();
    Assert::false($result, (string) $stmt->error);

    $result = $stmt->numRows();
    Assert::false($result, (string) $stmt->error);

    $result = $stmt->fieldCount();
    Assert::false($result, (string) $stmt->error);

    $result = $stmt->fetchObject();
    Assert::false($result, (string) $stmt->error);

    $result = $stmt->fetchAssoc();
    Assert::false($result, (string) $stmt->error);

    $result = $stmt->fetchArray();
    Assert::false($result, (string) $stmt->error);

    $result = $stmt->fetchRow();
    Assert::false($result, (string) $stmt->error);
});
?>
--EXPECT--
