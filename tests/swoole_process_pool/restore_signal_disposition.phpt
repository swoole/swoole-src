--TEST--
swoole_process_pool: restore signal disposition
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Event;
use Swoole\Process;
use Swoole\Process\Pool;

function run_in_child(Closure $fn): array
{
    $process = new Process($fn);
    $pid     = $process->start();
    // the pool master resets ITIMER_REAL, so the deadline is enforced from here
    for ($i = 0; $i < 500; $i++) {
        $status = Process::wait(false);
        if ($status) {
            return $status;
        }
        usleep(10000);
    }
    Process::kill($pid, SIGKILL);
    return Process::wait();
}

function start_pool(bool $rejected): void
{
    $pool = new Pool(1);
    if ($rejected) {
        $pool->on('workerExit', function () {});
        try {
            $pool->start();
        } catch (Swoole\Exception $exception) {
            Assert::same($exception->getMessage(), 'cannot set `onWorkerExit` without enable_coroutine');
        }
    } else {
        $pool->on('workerStart', function (Pool $pool) {
            $pool->shutdown();
        });
        $pool->start();
    }
}

foreach ([false, true] as $rejected) {
    $status = run_in_child(function () use ($rejected) {
        start_pool($rejected);
        Process::kill(getmypid(), SIGIO);
        usleep(100000);
        exit(99);
    });
    Assert::same($status['signal'], SIGIO);
}

foreach ([true, false] as $signalfd) {
    foreach ([false, true] as $rejected) {
        $status = run_in_child(function () use ($signalfd, $rejected) {
            swoole_async_set(['enable_signalfd' => $signalfd, 'wait_signal' => true]);
            $handled = false;
            Process::signal(SIGTERM, function () use (&$handled) {
                $handled = true;
                Event::exit();
            });
            // thread context builds register the signal in a deferred task
            Event::defer(function () {});
            Event::dispatch();

            start_pool($rejected);

            Event::defer(function () {
                Process::kill(getmypid(), SIGTERM);
            });
            Event::wait();
            exit($handled ? 0 : 1);
        });
        Assert::same($status['signal'], 0);
        Assert::same($status['code'], 0);
    }
}

$status = run_in_child(function () {
    swoole_async_set(['log_level' => SWOOLE_LOG_ERROR]);
    Process::signal(SIGUSR1, function () {});
    Event::defer(function () {});
    Event::dispatch();

    $starts   = new Atomic();
    $survived = new Atomic();
    $pool     = new Pool(1);
    $pool->on('workerStart', function (Pool $pool) use ($starts, $survived) {
        // the worker has no SIGTERM handler, so the default action must end it
        if ($starts->add() === 1) {
            Process::kill(getmypid(), SIGTERM);
            usleep(100000);
            $survived->set(1);
        }
        $pool->shutdown();
    });
    $pool->start();
    exit($survived->get());
});
Assert::same($status['signal'], 0);
Assert::same($status['code'], 0);

echo "DONE\n";
?>
--EXPECT--
DONE
