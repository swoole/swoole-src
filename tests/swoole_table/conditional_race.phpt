--TEST--
swoole_table: conditional operations are atomic across processes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Process;
use Swoole\Table;

const WORKERS = 4;

function race(callable $operation): int
{
    $ready     = new Atomic(0);
    $start     = new Atomic(0);
    $successes = new Atomic(0);
    $processes = [];

    for ($i = 0; $i < WORKERS; $i++) {
        $process = new Process(function () use ($ready, $start, $successes, $operation): void {
            $ready->add();
            while ($start->get() === 0) {
                usleep(1000);
            }
            if ($operation()) {
                $successes->add();
            }
        });
        Assert::greaterThan($process->start(), 0);
        $processes[] = $process;
    }

    $deadline = microtime(true) + 5;
    while ($ready->get() !== WORKERS) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('workers did not become ready');
        }
        usleep(1000);
    }

    $start->set(1);
    foreach ($processes as $_) {
        $status = Process::wait();
        Assert::same($status['code'], 0);
    }

    return $successes->get();
}

$table = new Table(128);
$table->column('value', Table::TYPE_INT);
$table->column('version', Table::TYPE_INT);
$table->create();

Assert::same(race(fn (): bool => $table->add('add', ['value' => 1])), 1);

$table->set('getdel', ['value' => 1]);
Assert::same(race(fn (): bool => $table->getdel('getdel') !== false), 1);

$table->set('cmpdel', ['value' => 1]);
Assert::same(race(fn (): bool => $table->cmpdel('cmpdel', ['value' => 1])), 1);

$table->set('counter', ['value' => 0, 'version' => 0]);
$iterations = 50;
Assert::same(race(function () use ($table, $iterations): bool {
    for ($i = 0; $i < $iterations; $i++) {
        do {
            $current = $table->get('counter');
        } while (!$table->cmpset(
            'counter',
            ['version' => $current['version']],
            [
                'value'   => $current['value'] + 1,
                'version' => $current['version'] + 1,
            ],
        ));
    }
    return true;
}), WORKERS);

$counter = $table->get('counter');
Assert::same($counter['value'], WORKERS * $iterations);
Assert::same($counter['version'], WORKERS * $iterations);
?>
--EXPECT--
