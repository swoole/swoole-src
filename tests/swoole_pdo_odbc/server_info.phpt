--TEST--
swoole_pdo_odbc: test hook pgsql
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.1');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(static function (): void {
    $pdo = new PDO(ODBC_DSN);
    $info = $pdo->getAttribute(PDO::ATTR_SERVER_INFO);
    Assert::eq(strtolower($info), 'mysql');
});

echo "Done\n";
?>
--EXPECTF--
Done
