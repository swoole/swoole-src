--TEST--
swoole_pgsql_coro: no field name
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\run(function () {
    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect(PGSQL_CONNECTION_STRING);
    Assert::true($connected, (string) $pgsql->error);

    $stmt = $pgsql->query('SELECT 11, 22');
    Assert::true(false !== $stmt, (string) $pgsql->error);

    $arr = $stmt->fetchAll();
    Assert::isArray($arr);
    Assert::eq($arr[0]['?column?'], 11);
    Assert::eq($arr[0]['?column?1'], 22);
});
?>
--EXPECT--
