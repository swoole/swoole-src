--TEST--
swoole_pdo_firebird: PDO::connect() returns Pdo\Firebird
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_firebird.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('pdo_firebird');
PdoFirebirdTest::skip();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$connection = PDO::connect(FIREBIRD_DSN, FIREBIRD_USER, FIREBIRD_PASSWORD);

Assert::true($connection instanceof Pdo\Firebird);

echo "DONE\n";
?>
--EXPECT--
DONE
