--TEST--
swoole_table: conditional conversion happens before locking
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

class NestedUpdate
{
    public function __construct(private Table $table)
    {
    }

    public function __toString(): string
    {
        Assert::true($this->table->update('row', ['id' => 2]));

        return 'original';
    }
}

class ConversionProbe
{
    public bool $called = false;

    public function __toString(): string
    {
        $this->called = true;

        return 'original';
    }
}

class DestroyDuringConversion
{
    public function __construct(private Table $table)
    {
    }

    public function __toString(): string
    {
        $this->table->destroy();

        return 'original';
    }
}

$table = new Table(128);
$table->column('id', Table::TYPE_INT);
$table->column('name', Table::TYPE_STRING, 16);
$table->column('score', Table::TYPE_FLOAT);
$table->create();
$table->set('row', ['id' => 1, 'name' => 'original', 'score' => 1.0]);

Assert::true($table->cmpset(
    'row',
    ['name'  => new NestedUpdate($table)],
    ['score' => 2.0],
));
Assert::same($table->get('row'), [
    'id'    => 2,
    'name'  => 'original',
    'score' => 2.0,
]);

$probe          = new ConversionProbe();
$errorReporting = error_reporting(0);
Assert::false($table->cmpset(
    'row',
    ['name' => $probe, 'missing' => 1],
    ['id'   => 3],
));
error_reporting($errorReporting);
Assert::false($probe->called);
Assert::same($table->get('row'), [
    'id'    => 2,
    'name'  => 'original',
    'score' => 2.0,
]);

try {
    $table->cmpset(
        'row',
        ['name' => new DestroyDuringConversion($table)],
        ['id'   => 3],
    );
    Assert::true(false);
} catch (Error $error) {
    Assert::contains($error->getMessage(), 'Cannot destroy Swoole\Table during value conversion');
}
Assert::same($table->get('row'), [
    'id'    => 2,
    'name'  => 'original',
    'score' => 2.0,
]);
?>
--EXPECT--
