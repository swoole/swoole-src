--TEST--
swoole_table: get and delete
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

$table = new Table(128);
$table->column('id', Table::TYPE_INT);
$table->column('name', Table::TYPE_STRING, 16);
$table->column('score', Table::TYPE_FLOAT);
$table->create();

$binary = "a\0b";
$table->set('row', ['id' => 42, 'name' => $binary, 'score' => 3.5]);
Assert::same($table->getdel('row'), [
    'id'    => 42,
    'name'  => $binary,
    'score' => 3.5,
]);
Assert::false($table->get('row'));
Assert::false($table->getdel('row'));

$table->set('id', ['id' => 7, 'name' => 'id', 'score' => 1.0]);
Assert::same($table->getdel('id', 'id'), 7);
Assert::false($table->get('id'));

$table->set('score', ['id' => 8, 'name' => 'score', 'score' => 2.5]);
Assert::same($table->getdel('score', 'score'), 2.5);
Assert::false($table->get('score'));

$table->set('name', ['id' => 9, 'name' => $binary, 'score' => 3.0]);
Assert::same($table->getdel('name', 'name'), $binary);
Assert::false($table->get('name'));

$table->set('unknown', ['id' => 10, 'name' => 'kept', 'score' => 4.0]);
Assert::false($table->getdel('unknown', 'missing'));
Assert::same($table->get('unknown', 'name'), 'kept');
?>
--EXPECT--
