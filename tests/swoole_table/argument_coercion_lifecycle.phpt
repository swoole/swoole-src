--TEST--
swoole_table: argument coercion lifecycle
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Table;

final class DestroyingString
{
    public function __construct(
        private Table $table,
        private string $value,
    ) {
    }

    public function __toString(): string
    {
        $this->table->destroy();

        return $this->value;
    }
}

function assertLifecycleFailure(Closure $operation): void
{
    $process = new Process(function () use ($operation): void {
        $table = new Table(8);
        $table->column('id', Table::TYPE_INT);
        $table->create();
        $table->set('row', ['id' => 1]);

        $operation($table);
    }, true, SOCK_STREAM);

    $process->start();
    $output = $process->read();
    $status = Process::wait();

    Assert::contains($output, 'must call constructor first');
    Assert::same($status['code'], 255);
    Assert::same($status['signal'], 0);
}

assertLifecycleFailure(
    fn (Table $table) => $table->column(new DestroyingString($table, 'other'), Table::TYPE_INT),
);
assertLifecycleFailure(
    fn (Table $table) => $table->set(new DestroyingString($table, 'row'), ['id' => 2]),
);
assertLifecycleFailure(
    fn (Table $table) => $table->get(new DestroyingString($table, 'row')),
);
assertLifecycleFailure(
    fn (Table $table) => $table->get('row', new DestroyingString($table, 'id')),
);
assertLifecycleFailure(
    fn (Table $table) => $table->exists(new DestroyingString($table, 'row')),
);
assertLifecycleFailure(
    fn (Table $table) => $table->del(new DestroyingString($table, 'row')),
);
assertLifecycleFailure(
    fn (Table $table) => $table->incr(new DestroyingString($table, 'row'), 'id'),
);
assertLifecycleFailure(
    fn (Table $table) => $table->decr('row', new DestroyingString($table, 'id')),
);
?>
--EXPECT--
