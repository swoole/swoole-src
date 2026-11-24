--TEST--
swoole_process_pool: message bus setup failure preserves pending reactor work and signals
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Process;
use Swoole\Process\Pool;
use Swoole\Timer;

foreach ([true, false] as $signalfd) {
    $process = new Process(function () use ($signalfd) {
        swoole_async_set(['enable_signalfd' => $signalfd, 'wait_signal' => true, 'log_level' => SWOOLE_LOG_ERROR]);
        $deferred = $fired = $handled = false;
        Process::signal(SIGUSR1, function () use (&$handled) {
            $handled = true;
            Event::exit();
        });
        // Complete deferred signal registration on thread-context builds before testing startup failure.
        Event::defer(function () {});
        Event::dispatch();

        Event::defer(function () use (&$deferred) {
            $deferred = true;
        });
        Timer::after(1, function () use (&$fired) {
            $fired = true;
            Process::kill(getmypid(), SIGUSR1);
        });

        $pool = new Pool(1, SWOOLE_IPC_NONE);
        $pool->set(['enable_message_bus' => true]); // Message bus requires SWOOLE_IPC_UNIXSOCK.
        $pool->on('WorkerStart', function (Pool $pool) {
            $pool->shutdown();
        });
        if ($pool->start() !== false) {
            exit(2);
        }
        Event::wait();
        exit($deferred && $fired && $handled ? 0 : 1);
    });
    $pid = $process->start();
    $status = false;
    for ($i = 0; $i < 300; $i++) {
        $status = Process::wait(false);
        if ($status) {
            break;
        }
        usleep(10000);
    }
    if (!$status) {
        Process::kill($pid, SIGKILL);
        $status = Process::wait();
    }
    Assert::same($status['signal'], 0);
    Assert::same($status['code'], 0);
}
echo "DONE\n";
?>
--EXPECT--
DONE
