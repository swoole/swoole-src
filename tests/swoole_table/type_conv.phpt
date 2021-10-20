--TEST--
swoole_table: type convert
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const PI =  3.1415926;
const NAME = 'rango';

$table = new swoole_table(65536);

$table->column('id', swoole_table::TYPE_INT);
$table->column('name', swoole_table::TYPE_STRING, 128);
$table->column('num', swoole_table::TYPE_FLOAT);

if (!$table->create()) {
    echo __LINE__." error";
}

$table->set('test_key', array('id' => 1, 'name' => NAME, 'num' => PI));
$table->set(1002, array('id' => '2', 'name' => 'hello', 'num' => PI + 9));

$r1 = ($table->get('test_key'));
$r2 = ($table->get(1002));

Assert::same($r1['id'], 1);
Assert::same($r2['id'], 2);

$table->set('test_key', array('id' => '2348', 'name' => 1024, 'num' => '3.231'));
$r1 = ($table->get('test_key'));

Assert::same($r1['id'], 2348);
Assert::same($r1['num'], 3.231);
Assert::same($r1['name'], '1024');

$table->set('test_key', array('id' => 'abc', 'name' => 1024, 'num' => '3.231'));
$r1 = ($table->get('test_key'));
Assert::same($r1['id'], 0);

?>
--EXPECT--
