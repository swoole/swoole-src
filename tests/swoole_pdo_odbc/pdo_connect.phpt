--TEST--
swoole_pdo_odbc: PDO::connect() returns Pdo\Odbc
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/bootstrap.php';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('pdo_odbc');
try {
    new PDO(ODBC_DSN);
} catch (PDOException $e) {
    skip($e->getMessage());
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$connection = PDO::connect(ODBC_DSN);

Assert::true($connection instanceof Pdo\Odbc);

echo "DONE\n";
?>
--EXPECT--
DONE
