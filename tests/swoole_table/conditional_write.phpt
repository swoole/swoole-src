--TEST--
swoole_table: conditional writes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

$table = new Table(128);
$table->column('id', Table::TYPE_INT);
$table->column('name', Table::TYPE_STRING, 32);
$table->column('score', Table::TYPE_FLOAT);
$table->column('version', Table::TYPE_INT);
$table->create();

Assert::true($table->add('empty', []));
Assert::same($table->get('empty'), [
    'id'      => 0,
    'name'    => '',
    'score'   => 0.0,
    'version' => 0,
]);

Assert::true($table->add('row', [
    'id'      => 1,
    'name'    => 'first',
    'score'   => 1.5,
    'version' => 1,
]));
Assert::false($table->add('row', ['name' => 'replaced']));
Assert::same($table->get('row')['name'], 'first');

Assert::false($table->update('missing', ['id' => 2]));
Assert::true($table->update('row', ['name' => 'updated']));
Assert::same($table->get('row'), [
    'id'      => 1,
    'name'    => 'updated',
    'score'   => 1.5,
    'version' => 1,
]);
Assert::true($table->update('row', []));
Assert::true($table->update('row', [0 => 99, 'missing' => 99]));
Assert::same($table->get('row')['id'], 1);

Assert::false($table->cmpset('missing', ['version' => 1], ['version' => 2]));
Assert::false($table->cmpset('row', ['id' => 2], ['name' => 'wrong']));
Assert::same($table->get('row')['name'], 'updated');
Assert::true($table->cmpset(
    'row',
    ['id'   => 1, 'name' => 'updated', 'version' => 1],
    ['name' => 'compared', 'version' => 2],
));
Assert::same($table->get('row')['name'], 'compared');
Assert::same($table->get('row')['version'], 2);
Assert::true($table->cmpset('row', ['version' => 2], []));
Assert::true($table->cmpset('row', ['version' => 2], [0 => 1, 'missing' => 1]));

Assert::true($table->add('ignored', [
    0         => 99,
    'missing' => 99,
    'id'      => 2,
]));
Assert::same($table->get('ignored'), [
    'id'      => 2,
    'name'    => '',
    'score'   => 0.0,
    'version' => 0,
]);
?>
--EXPECT--
