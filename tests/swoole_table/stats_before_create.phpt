--TEST--
swoole_table: stats before create
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$table = new Swoole\Table(8);
var_dump($table->stats());

$table->column('id', Swoole\Table::TYPE_INT);
$table->create();
var_dump(is_array($table->stats()));

$table->destroy();
var_dump($table->stats());
?>
--EXPECT--
bool(false)
bool(true)
bool(false)
