--TEST--
swoole_table: argument metadata matches count modes and numeric value conversion
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
declare(strict_types=1);
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

$table = new Table(8);
$table->column('number', Table::TYPE_INT);
$table->column('score', Table::TYPE_FLOAT);
$table->create();
$table->set('first', ['number' => 1, 'score' => 1.5]);
$table->set('second', ['number' => 2, 'score' => 2.5]);

Assert::same(count($table), 2);
Assert::same($table->count(COUNT_NORMAL), 2);
Assert::same($table->count(mode: COUNT_RECURSIVE), 4);
Assert::same($table->incr('first', 'number', '2'), 3);
Assert::same($table->decr('first', 'score', '0.5'), 1.0);
Assert::same($table->incr('first', 'number'), 4);

$method = new ReflectionMethod(Table::class, 'count');
Assert::same($method->getNumberOfParameters(), 1);
Assert::same($method->getNumberOfRequiredParameters(), 0);
Assert::same($method->getParameters()[0]->getDefaultValue(), COUNT_NORMAL);

// These methods still accept no arguments; they must not share count()'s optional-mode arginfo.
foreach (['getSize', 'getMemorySize'] as $name) {
    Assert::same((new ReflectionMethod(Table::class, $name))->getNumberOfParameters(), 0);
    Assert::greaterThan($table->$name(), 0);
}
?>
--EXPECT--
