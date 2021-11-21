--TEST--
swoole_table: negative
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$table = new Swoole\Table(65536);

$table->column('v1', Swoole\Table::TYPE_INT);
$table->column('v2', Swoole\Table::TYPE_FLOAT);

if (!$table->create())
{
    echo __LINE__." error";
}
$table->set('test1', ['v1' => 0, 'v2' => 0]);

Assert::same($table->decr('test1', 'v1', 1), -1);
Assert::same($table->decr('test1', 'v2', 1.5), -1.5);

?>
--EXPECT--
