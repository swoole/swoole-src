--TEST--
swoole_pdo_pgsql: PDO::connect() returns Pdo\Pgsql
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_pgsql.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('pdo_pgsql');
try {
    pdo_pgsql_test_inc::create();
} catch (PDOException $e) {
    skip($e->getMessage());
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$dsn = sprintf(
    'pgsql:host=%s;port=%d;dbname=%s',
    PGSQL_HOST,
    PGSQL_PORT,
    PGSQL_DBNAME
);
$connection = PDO::connect($dsn, PGSQL_USER, PGSQL_PASSWORD);

Assert::true($connection instanceof Pdo\Pgsql);

echo "DONE\n";
?>
--EXPECT--
DONE
