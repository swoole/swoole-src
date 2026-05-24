--TEST--
swoole_runtime: Github#6067 https://github.com/swoole/swoole-src/issues/6067
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (PHP_VERSION_ID < 80400) {
    skip('php version 8.4 or newer');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;

run(function() {
    // sqlite
    $connection = PDO::connect('sqlite::memory:');
    Assert::true($connection instanceof \Pdo\Sqlite);

    // pgsql
    $host = PGSQL_HOST;
    $port = PGSQL_PORT;
    $user = PGSQL_USER;
    $password = PGSQL_PASSWORD;
    $dbname = PGSQL_DBNAME;
    $connection = PDO::connect("pgsql:host={$host};port={$port};dbname={$dbname}", $user, $password);
    var_dump($connection);
    Assert::true($connection instanceof \Pdo\Pgsql);

    // odbc
    $connection = PDO::connect(ODBC_DSN);
    var_dump($connection);
    Assert::true($connection instanceof \Pdo\Odbc);
});
?>
--EXPECT--
