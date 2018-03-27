--TEST--
swoole_table: int

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>

--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
$table = new swoole_table(65536);

$table->column('i8', swoole_table::TYPE_INT, 1);
$table->column('i16', swoole_table::TYPE_INT, 2);
$table->column('i32', swoole_table::TYPE_INT, 4);
$table->column('i64', swoole_table::TYPE_INT, 8);

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

assert($ret['i8'] == -120);
assert($ret['i16'] == -30000);
assert($ret['i32'] == -1247483648);
assert($ret['i64'] == -9023372036854775808);

$ret = $table->incr('test_key', 'i8', 8);
if (!$ret)
{
    echo __LINE__." error";
}
assert($table->get('test_key', 'i8') == -120 + 8);

$ret = $table->decr('test_key', 'i32', 8);
if (!$ret)
{
    echo __LINE__." error";
}
assert($table->get('test_key', 'i32') == -1247483648 - 8);


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

assert($ret['i8'] == 120);
assert($ret['i16'] == 30000);
assert($ret['i32'] == 1247483648);
assert($ret['i64'] == 9023372036854775808);

$ret = $table->incr('test_key', 'i8', 4);
if (!$ret)
{
    echo __LINE__." error";
}
assert($table->get('test_key', 'i8') == 120 + 4);

$ret = $table->decr('test_key', 'i32', 8);
if (!$ret)
{
    echo __LINE__." error";
}
assert($table->get('test_key', 'i32') == 1247483648 - 8);

echo "SUCCESS";
?>

--EXPECT--
SUCCESS