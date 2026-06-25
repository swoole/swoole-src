--TEST--
swoole_table: duplicate column names are rejected
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$table = new Swoole\Table(8);
var_dump($table->column('id', Swoole\Table::TYPE_INT));
var_dump($table->column('id', Swoole\Table::TYPE_STRING, 8));
$table->create();
$table->set('k', ['id' => 123]);
var_dump($table->get('k'));
?>
--EXPECTF--
bool(true)
%sWARNING%sTable::add_column(): column[id] already exists
bool(false)
array(1) {
  ["id"]=>
  int(123)
}
