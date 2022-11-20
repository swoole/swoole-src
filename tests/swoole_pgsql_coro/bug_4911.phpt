--TEST--
swoole_pgsql_coro: bug 4911 https://github.com/swoole/swoole-src/issues/4911
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\run(function () {
    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect('host=pgsql;port=5432;dbname=test123123;user=root;password=root');
    echo $pgsql->error.PHP_EOL;

    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect('host=pgsql;port=5432;dbname=test;user=root123;password=root');
    echo $pgsql->error.PHP_EOL;

    $pgsql = new Swoole\Coroutine\PostgreSQL();
    $connected = $pgsql->connect('host=pgsql;port=5432;dbname=test;user=root;password=');
    echo $pgsql->error.PHP_EOL;
});
?>
--EXPECT--
FATAL:  database "test123123" does not exist

FATAL:  password authentication failed for user "root123"

fe_sendauth: no password supplied

