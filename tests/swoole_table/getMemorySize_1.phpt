--TEST--
swoole_table: getMemorySize
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

$table = new Table(2);
Assert::eq($table->getMemorySize(), 0);
$table->column('name', Table::TYPE_STRING, 32);
$table->create();
Assert::greaterThan($table->getMemorySize(), 0);
?>
--EXPECTF--
