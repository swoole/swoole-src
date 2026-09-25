--TEST--
swoole_coroutine_system: queued lock holder expands the AIO thread pool
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_defined('SWOOLE_HOOK_PDO_SQLITE');
?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\System;

use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

swoole_async_set([
    'aio_core_worker_num' => 2,
    'aio_worker_num' => 4,
]);
Coroutine::set(['hook_flags' => SWOOLE_HOOK_PDO_SQLITE]);

require __DIR__ . '/../include/bootstrap.php';

$database = __DIR__ . '/aio_worker_scheduling.db';
$dsn = 'sqlite:' . $database;
@unlink($database);
@unlink($database . '-journal');

run(function () use ($dsn) {
    // Start the pool before SQLite setup so setup tasks cannot affect the saturation boundary.
    System::readFile(__FILE__);
    System::sleep(0.05);
    $workerNum = Coroutine::stats()['aio_worker_num'];

    $holder = new PDO($dsn, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $holder->exec('CREATE TABLE counter (value INTEGER NOT NULL)');
    $holder->exec('INSERT INTO counter VALUES (0)');

    $waiters = [];
    for ($i = 0; $i < 3; $i++) {
        $waiters[$i] = new PDO($dsn, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $waiters[$i]->exec('PRAGMA busy_timeout = 5000');
    }

    $holder->exec('BEGIN IMMEDIATE');
    $holder->exec('UPDATE counter SET value = value + 1');

    System::sleep(0.05);
    Assert::same(Coroutine::stats()['aio_worker_num'], $workerNum);
    if ($workerNum >= 4) {
        throw new RuntimeException('AIO pool has no capacity for the regression test');
    }
    $waiters = array_slice($waiters, 0, $workerNum);

    $started = new Channel(1);
    $results = new Channel($workerNum);

    foreach ($waiters as $index => $waiter) {
        go(function () use ($waiter, $started, $results) {
            $started->push(true);
            try {
                $waiter->exec('UPDATE counter SET value = value + 1');
                $results->push(true);
            } catch (Throwable $exception) {
                $results->push($exception->getMessage());
            }
        });

        $started->pop();
        $deadline = microtime(true) + 2;
        do {
            $stats = Coroutine::stats();
            if ($stats['aio_task_num'] === $index + 1 &&
                $stats['aio_worker_num'] === $workerNum &&
                $stats['aio_queue_size'] === 0) {
                break;
            }
            System::sleep(0.001);
        } while (microtime(true) < $deadline);

        Assert::same($stats['aio_task_num'], $index + 1);
        Assert::same($stats['aio_worker_num'], $workerNum);
        Assert::same($stats['aio_queue_size'], 0);
    }

    $holder->exec('COMMIT');
    Assert::same(Coroutine::stats()['aio_worker_num'], $workerNum + 1);

    for ($i = 0; $i < $workerNum; $i++) {
        Assert::true($results->pop(5));
    }
    Assert::same($holder->query('SELECT value FROM counter')->fetchColumn(), $workerNum + 1);
});

echo "DONE\n";
?>
--CLEAN--
<?php
@unlink(__DIR__ . '/aio_worker_scheduling.db');
@unlink(__DIR__ . '/aio_worker_scheduling.db-journal');
?>
--EXPECT--
DONE
