--TEST--
swoole_table: invalid keys are rejected
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$table = new Swoole\Table(8);
$table->column('id', Swoole\Table::TYPE_INT);
$table->create();

var_dump($table->set('', ['id' => 1]));
var_dump($table->set(str_repeat('a', 64), ['id' => 2]));
var_dump($table->get(str_repeat('a', 64)));
var_dump($table->exists(str_repeat('a', 64)));
var_dump($table->del(str_repeat('a', 64)));
var_dump(count($table));
?>
--EXPECTF--
Warning: Swoole\Table::set(): key must not be empty in %s on line %d
bool(false)

Warning: Swoole\Table::set(): key length exceeds the limit of 63 bytes in %s on line %d
bool(false)

Warning: Swoole\Table::get(): key length exceeds the limit of 63 bytes in %s on line %d
bool(false)

Warning: Swoole\Table::exists(): key length exceeds the limit of 63 bytes in %s on line %d
bool(false)

Warning: Swoole\Table::del(): key length exceeds the limit of 63 bytes in %s on line %d
bool(false)
int(0)
