--TEST--
swoole_table: conditional validation
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

$table = new Table(128);
$table->column('id', Table::TYPE_INT);
$table->column('name', Table::TYPE_STRING, 16);
$table->create();
$table->set('row', ['id' => 1, 'name' => 'original']);

function assertUnchanged(Table $table, array $stats): void
{
    Assert::same($table->get('row'), ['id' => 1, 'name' => 'original']);
    Assert::same($table->stats(), $stats);
}

$stats = $table->stats();

var_dump($table->cmpset('row', [], ['id' => 2]));
assertUnchanged($table, $stats);

var_dump($table->cmpset('row', [1], ['id' => 2]));
assertUnchanged($table, $stats);

var_dump($table->cmpdel('row', ['missing' => 1]));
assertUnchanged($table, $stats);

var_dump($table->cmpset('row', ['id' => 1, 'missing' => 1], ['id' => 2]));
assertUnchanged($table, $stats);

var_dump($table->add('', ['id' => 2]));
var_dump($table->update('', ['id' => 2]));
var_dump($table->cmpset('', ['id' => 1], ['id' => 2]));
var_dump($table->cmpdel('', ['id' => 1]));
var_dump($table->getdel(''));
assertUnchanged($table, $stats);
?>
--EXPECTF--
Warning: Swoole\Table::cmpset(): expected values must not be empty in %s on line %d
bool(false)

Warning: Swoole\Table::cmpset(): expected values must use column names in %s on line %d
bool(false)

Warning: Swoole\Table::cmpdel(): column[missing] does not exist in %s on line %d
bool(false)

Warning: Swoole\Table::cmpset(): column[missing] does not exist in %s on line %d
bool(false)

Warning: Swoole\Table::add(): key must not be empty in %s on line %d
bool(false)

Warning: Swoole\Table::update(): key must not be empty in %s on line %d
bool(false)

Warning: Swoole\Table::cmpset(): key must not be empty in %s on line %d
bool(false)

Warning: Swoole\Table::cmpdel(): key must not be empty in %s on line %d
bool(false)

Warning: Swoole\Table::getdel(): key must not be empty in %s on line %d
bool(false)
