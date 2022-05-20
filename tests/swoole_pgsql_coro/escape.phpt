--TEST--
swoole_pgsql_coro: escape
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\run(function () {
    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect(PGSQL_CONNECTION_STRING);
    Assert::true($connected, (string) $pgsql->error);

    $result = $pgsql->escape("' or 1=1 & 2");
    Assert::true(false !== $result, (string) $pgsql->error);
    Assert::eq($result, "'' or 1=1 & 2");
});
?>
--EXPECT--
