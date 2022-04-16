--TEST--
swoole_table: int
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$table = new Swoole\Table(65536);

$table->column('i8', Swoole\Table::TYPE_INT, 1);
$table->column('i16', Swoole\Table::TYPE_INT, 2);
$table->column('i32', Swoole\Table::TYPE_INT, 4);
$table->column('i64', Swoole\Table::TYPE_INT, 8);

if (!$table->create())
{
    echo __LINE__." error";
}

$ret = $table->set('test_key', array(
    'i8' => -120,
    'i16' => -30000,
    'i32' => -1247483648,
    'i64' => -9023372036854775808,
));
if (!$ret)
{
    echo __LINE__." error";
}

$ret = $table->get('test_key');
if (!$ret)
{
    echo __LINE__." error";
}

Assert::same($ret['i8'], -120);
Assert::same($ret['i16'], -30000);
Assert::same($ret['i32'], -1247483648);
Assert::same($ret['i64'], -9023372036854775808);

$ret = $table->incr('test_key', 'i8', 8);
if (!$ret)
{
    echo __LINE__." error";
}
Assert::same($table->get('test_key', 'i8'), -120 + 8);

$ret = $table->decr('test_key', 'i32', 8);
if (!$ret)
{
    echo __LINE__." error";
}
Assert::same($table->get('test_key', 'i32'), -1247483648 - 8);

$ret = $table->set('test_key', array(
    'i8' => 120,
    'i16' => 30000,
    'i32' => 1247483648,
    'i64' => 9023372036854775808,
));
if (!$ret)
{
    echo __LINE__." error";
}

$ret = $table->get('test_key');
if (!$ret)
{
    echo __LINE__." error";
}

Assert::same($ret['i8'], 120);
Assert::same($ret['i16'], 30000);
Assert::same($ret['i32'], 1247483648);
Assert::same($ret['i64'], 9023372036854775808);

$ret = $table->incr('test_key', 'i8', 4);
if (!$ret)
{
    echo __LINE__." error";
}
Assert::same($table->get('test_key', 'i8'), 120 + 4);

$ret = $table->decr('test_key', 'i32', 8);
if (!$ret)
{
    echo __LINE__." error";
}
Assert::same($table->get('test_key', 'i32'), 1247483648 - 8);

echo "SUCCESS";
?>
--EXPECT--
SUCCESS
