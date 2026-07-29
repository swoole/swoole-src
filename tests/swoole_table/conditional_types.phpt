--TEST--
swoole_table: conditional value types
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

$table = new Table(128);
$table->column('id', Table::TYPE_INT);
$table->column('name', Table::TYPE_STRING, 8);
$table->column('score', Table::TYPE_FLOAT);
$table->create();

Assert::true($table->add('coerce', [
    'id'    => '42',
    'name'  => null,
    'score' => '1.25',
]));
Assert::same($table->get('coerce'), [
    'id'    => 42,
    'name'  => '',
    'score' => 1.25,
]);
Assert::true($table->cmpset(
    'coerce',
    ['id' => '42', 'name' => null, 'score' => '1.25'],
    [],
));

$binary = "a\0b";
Assert::true($table->add('binary', ['name' => $binary]));
Assert::true($table->cmpset('binary', ['name' => $binary], []));
Assert::false($table->cmpset('binary', ['name' => "a\0c"], []));

Assert::true($table->add('long', ['name' => str_repeat('x', 16)]));
Assert::same($table->get('long', 'name'), str_repeat('x', 8));
Assert::false($table->cmpset('long', ['name' => str_repeat('x', 16)], []));

Assert::true($table->add('zero', ['score' => 0.0]));
Assert::false($table->cmpset('zero', ['score' => -0.0], []));
Assert::true($table->cmpset('zero', ['score' => 0.0], []));

Assert::true($table->add('nan', ['score' => NAN]));
$nan = $table->get('nan', 'score');
Assert::true(is_nan($nan));
Assert::true($table->cmpset('nan', ['score' => $nan], []));
?>
--EXPECTF--
[%s]	WARNING	table_marshal_values(): [key=long,field=name]string value is too long
