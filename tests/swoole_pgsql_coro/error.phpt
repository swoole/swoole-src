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
});
?>
--EXPECT--
