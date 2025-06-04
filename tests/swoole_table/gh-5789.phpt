--TEST--
swoole_table: bug_5789
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

$table = new Table(128, 1);
$table->column('test', Table::TYPE_INT);
$table->create();

$value = random_int(1, PHP_INT_MAX);
$table->set('firstrow', ['test' => $value]);

Assert::eq($table->get('firstrow', 'test'), $value);
Assert::eq($table->get('firstrow', null), ['test' => $value]);
Assert::same($table->get('not-exists', null), false);
Assert::same($table->get('not-exists', 'test'), false);
?>
--EXPECT--
