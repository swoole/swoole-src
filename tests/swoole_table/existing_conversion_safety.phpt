--TEST--
swoole_table: existing operation conversion safety
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Table;

final class NestedUpdate
{
    public function __construct(private Table $table)
    {
    }

    public function __toString(): string
    {
        Assert::true($this->table->update('row', ['id' => 2]));

        return 'outer';
    }
}

final class DestroyDuringConversion
{
    public function __construct(private Table $table)
    {
    }

    public function __toString(): string
    {
        $this->table->destroy();

        return 'destroyed';
    }
}

final class ThrowingString
{
    public function __toString(): string
    {
        throw new RuntimeException('conversion failed');
    }
}

final class NumericValue
{
}

function assertRuntimeException(Closure $operation): void
{
    try {
        $operation();
        Assert::true(false);
    } catch (RuntimeException $exception) {
        Assert::same($exception->getMessage(), 'conversion failed');
    }
}

$table = new Table(128);
$table->column('id', Table::TYPE_INT);
$table->column('name', Table::TYPE_STRING, 16);
$table->column('score', Table::TYPE_FLOAT);
$table->create();
$table->set('row', ['id' => 1, 'name' => 'original', 'score' => 1.0]);

Assert::true($table->set('row', ['name' => new NestedUpdate($table)]));
Assert::same($table->get('row'), [
    'id'    => 2,
    'name'  => 'outer',
    'score' => 1.0,
]);

$row   = $table->get('row');
$stats = $table->stats();
try {
    $table->set('row', ['name' => new DestroyDuringConversion($table)]);
    Assert::true(false);
} catch (Error $error) {
    Assert::contains($error->getMessage(), 'Cannot destroy Swoole\Table during value conversion');
}
Assert::same($table->get('row'), $row);
Assert::same($table->stats(), $stats);

$row   = $table->get('row');
$stats = $table->stats();
assertRuntimeException(
    fn () => $table->set('row', ['id' => 3, 'name' => new ThrowingString()]),
);
Assert::same($table->get('row'), $row);
Assert::same($table->stats(), $stats);

$stats = $table->stats();
assertRuntimeException(
    fn () => $table->set('missing', ['id' => 3, 'name' => new ThrowingString()]),
);
Assert::false($table->exists('missing'));
Assert::same($table->stats(), $stats);

set_error_handler(function (int $severity, string $message) use ($table): bool {
    Assert::contains($message, 'could not be converted');
    Assert::true($table->update('row', ['score' => 10.0]));

    return true;
});
try {
    Assert::same($table->incr('row', 'score', new NumericValue()), 11.0);
} finally {
    restore_error_handler();
}
Assert::same($table->get('row')['score'], 11.0);

$row   = $table->get('row');
$stats = $table->stats();
set_error_handler(
    fn () => throw new RuntimeException('conversion failed'),
);
try {
    assertRuntimeException(
        fn () => $table->decr('row', 'id', new NumericValue()),
    );
    Assert::same($table->get('row'), $row);
    Assert::same($table->stats(), $stats);

    assertRuntimeException(
        fn () => $table->decr('missing', 'id', new NumericValue()),
    );
    Assert::false($table->exists('missing'));
    Assert::same($table->stats(), $stats);
} finally {
    restore_error_handler();
}

$row   = $table->get('row');
$stats = $table->stats();
set_error_handler(function () use ($table): bool {
    $table->destroy();

    return true;
});
try {
    try {
        $table->incr('row', 'id', new NumericValue());
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Cannot destroy Swoole\Table during value conversion');
    }
} finally {
    restore_error_handler();
}
Assert::same($table->get('row'), $row);
Assert::same($table->stats(), $stats);
?>
--EXPECT--
