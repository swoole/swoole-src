--TEST--
swoole_pdo_pgsql: libpq version
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$version = shell_exec('php --ri swoole');
Assert::true(str_contains($version, 'postgresql(libpq) version'));
?>
--EXPECTF--
