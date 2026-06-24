--TEST--
swoole_table: incr/decr invalid column should not insert rows
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$table = new Swoole\Table(8);
$table->column('id', Swoole\Table::TYPE_INT);
$table->column('name', Swoole\Table::TYPE_STRING, 8);
$table->create();

var_dump($table->incr('k1', 'missing'));
var_dump(count($table));
var_dump($table->get('k1'));

var_dump($table->incr('k2', 'name'));
var_dump(count($table));
var_dump($table->get('k2'));

var_dump($table->decr('k3', 'missing'));
var_dump(count($table));
var_dump($table->get('k3'));
?>
--EXPECTF--
Warning: Swoole\Table::incr(): column[missing] does not exist in %s on line %d
bool(false)
int(0)
bool(false)

Warning: Swoole\Table::incr(): can't execute 'incr' on a string type column in %s on line %d
bool(false)
int(0)
bool(false)

Warning: Swoole\Table::decr(): column[missing] does not exist in %s on line %d
bool(false)
int(0)
bool(false)
