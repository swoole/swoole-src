--TEST--
swoole_table: conditional operation statistics
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

$table = new Table(128);
$table->column('id', Table::TYPE_INT);
$table->column('version', Table::TYPE_INT);
$table->create();

function assertDelta(array $before, array $after, array $delta): void
{
    foreach (['num', 'insert_count', 'update_count', 'delete_count'] as $name) {
        Assert::same($after[$name], $before[$name] + ($delta[$name] ?? 0));
    }
}

$before = $table->stats();
Assert::true($table->add('row', ['id' => 1, 'version' => 1]));
$after = $table->stats();
assertDelta($before, $after, ['num' => 1, 'insert_count' => 1]);

$before = $after;
Assert::false($table->add('row', ['id' => 2]));
Assert::false($table->update('missing', ['id' => 2]));
Assert::false($table->cmpset('row', ['version' => 2], ['id' => 2]));
Assert::false($table->cmpdel('row', ['version' => 2]));
Assert::false($table->getdel('missing'));
Assert::false($table->getdel('row', 'missing'));
$errorReporting = error_reporting(0);
Assert::false($table->cmpset('row', [], ['id' => 2]));
error_reporting($errorReporting);
$after = $table->stats();
assertDelta($before, $after, []);

$before = $after;
Assert::true($table->update('row', []));
$after = $table->stats();
assertDelta($before, $after, ['update_count' => 1]);

$before = $after;
Assert::true($table->cmpset('row', ['version' => 1], ['id' => 2, 'version' => 2]));
$after = $table->stats();
assertDelta($before, $after, ['update_count' => 1]);

$before = $after;
Assert::true($table->cmpdel('row', ['version' => 2]));
$after = $table->stats();
assertDelta($before, $after, ['num' => -1, 'delete_count' => 1]);

$before = $after;
Assert::true($table->add('row', ['id' => 3]));
Assert::same($table->getdel('row', 'id'), 3);
$after = $table->stats();
assertDelta($before, $after, ['insert_count' => 1, 'delete_count' => 1]);

Assert::same($after['num'], 0);
Assert::same($after['available_slice_num'], $after['total_slice_num']);
?>
--EXPECT--
