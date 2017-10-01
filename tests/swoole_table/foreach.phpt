--TEST--
swoole_table: iterator

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

$table->column('id', swoole_table::TYPE_INT);
$table->column('name', swoole_table::TYPE_STRING, 128);
$table->column('num', swoole_table::TYPE_FLOAT);

if (!$table->create())
{
    echo __LINE__." error";
}
$table->set('test_key', array('id' => 1, 'name' => 'rango', 'num' => 3.1415926));
$table->set('hello_world', array('id' => 100, 'name' => 'xinhua', 'num' => 399.66));

$_key = array();
$_num = array();
foreach ($table as $key => $value)
{
    $_key [] = $key;
    $_num [] = $value['num'];
}
sort($_key);
sort($_num);
if (implode('', $_key) == 'hello_worldtest_key' and  array_sum($_num) == 399.66 + 3.1415926)
{
    echo 'SUCCESS';
}

?>

--EXPECT--
SUCCESS