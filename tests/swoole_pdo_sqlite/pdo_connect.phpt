--TEST--
swoole_pdo_sqlite: PDO::connect() returns Pdo\Sqlite
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('pdo_sqlite');
PdoSqliteTest::skip();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$connection = PDO::connect(SQLITE_DSN);

Assert::true($connection instanceof Pdo\Sqlite);
Assert::true(method_exists($connection, 'createFunction'));

echo "DONE\n";
?>
--EXPECT--
DONE
