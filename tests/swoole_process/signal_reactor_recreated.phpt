--TEST--
swoole_process: signal listener keeps working in a recreated event loop
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Process;

function run_in_child(Closure $fn): array
{
    $process = new Process($fn);
    $pid     = $process->start();
    for ($i = 0; $i < 300; $i++) {
        $status = Process::wait(false);
        if ($status) {
            return $status;
        }
        usleep(10000);
    }
    Process::kill($pid, SIGKILL);
    return Process::wait();
}

foreach ([true, false] as $signalfd) {
    $status = run_in_child(function () use ($signalfd) {
        swoole_async_set(['enable_signalfd' => $signalfd]);
        $handled = false;
        Process::signal(SIGUSR1, function () use (&$handled) {
            $handled = true;
            Event::exit();
        });
        // without wait_signal this loop returns at once and frees its reactor
        Event::wait();

        swoole_async_set(['wait_signal' => true]);
        Event::defer(function () {
            Process::kill(getmypid(), SIGUSR1);
        });
        Event::wait();
        exit($handled ? 0 : 1);
    });
    Assert::same($status['signal'], 0);
    Assert::same($status['code'], 0);
}

// a native listener keeps its dispatch in a loop that also reads a signalfd
$status = run_in_child(function () {
    swoole_async_set(['enable_signalfd' => false]);
    $handled = false;
    Process::signal(SIGUSR1, function () use (&$handled) {
        $handled = true;
        Event::exit();
    });
    Event::wait();

    swoole_async_set(['enable_signalfd' => true, 'wait_signal' => true]);
    Process::signal(SIGUSR2, function () {});
    // thread context builds register the signal in a deferred task
    Event::defer(function () {});
    Event::dispatch();

    Event::defer(function () {
        Process::kill(getmypid(), SIGUSR1);
    });
    Event::wait();
    exit($handled ? 0 : 1);
});
Assert::same($status['signal'], 0);
Assert::same($status['code'], 0);

echo "DONE\n";
?>
--EXPECT--
DONE
