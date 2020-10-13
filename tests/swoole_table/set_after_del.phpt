--TEST--
swoole_table: set after del
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$table = new \Swoole\Table(1024);
$table->column('id', \Swoole\Table::TYPE_INT);
$table->column('name', \Swoole\Table::TYPE_STRING, 10);
$table->create();

$table->set('1', ['id' => 1, 'name' => 'rango']);

Assert::eq($table->get('1')['id'], 1);
Assert::eq($table->get('1')['name'], 'rango');
Assert::true($table->del('1'));
Assert::false($table->get('1'));
$table->set('1', ['id' => 2, ]);

Assert::eq($table->get('1')['id'], 2);
Assert::eq($table->get('1')['name'], '');
?>
--EXPECT--
