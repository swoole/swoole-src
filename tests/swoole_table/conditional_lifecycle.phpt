--TEST--
swoole_table: conditional operation lifecycle guards
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Process;
use Swoole\Table;

class DestroyingKey
{
    public function __construct(private Table $table)
    {
    }

    public function __toString(): string
    {
        $this->table->destroy();

        return 'row';
    }
}

$process = new Process(function (): void {
    $table = new Table(128);
    $table->column('id', Table::TYPE_INT);
    $table->add('row', ['id' => 1]);
}, true, SOCK_STREAM);
$process->start();
$output = $process->read();
$status = Process::wait();
Assert::contains($output, 'table is not created or has been destroyed');
Assert::same($status['code'], 255);

$process = new Process(function (): void {
    $table = new Table(128);
    $table->column('id', Table::TYPE_INT);
    $table->create();
    $table->getdel(new DestroyingKey($table));
}, true, SOCK_STREAM);
$process->start();
$output = $process->read();
$status = Process::wait();
Assert::contains($output, 'must call constructor first');
Assert::same($status['code'], 255);

$table = new Table(128);
$table->column('id', Table::TYPE_INT);
$table->create();
$table->set('row', ['id' => 1]);
$destroyed = new Atomic(0);

$process = new Process(function () use ($table, $destroyed): void {
    while ($destroyed->get() === 0) {
        usleep(1000);
    }
    $table->getdel('row');
}, true, SOCK_STREAM);
$process->start();
$table->destroy();
$destroyed->set(1);
$output = $process->read();
$status = Process::wait();
Assert::contains($output, 'table is not created or has been destroyed');
Assert::same($status['code'], 255);
?>
--EXPECT--
