--TEST--
swoole_pgsql_coro: not connected
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\run(function () {
    $pgsql = new Swoole\Coroutine\PostgreSQL();

    Assert::false($pgsql->escape(''));
    Assert::false($pgsql->escapeLiteral(''));
    Assert::false($pgsql->escapeIdentifier(''));
    Assert::false($pgsql->query(''));
    Assert::false($pgsql->prepare(''));
    Assert::false($pgsql->metaData(''));
});
?>
--EXPECT--
