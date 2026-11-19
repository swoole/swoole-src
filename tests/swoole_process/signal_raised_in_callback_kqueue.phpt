--TEST--
swoole_process: kqueue dispatches a pending signal before waiting for a timer
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_darwin();
?>
--FILE--
<?php
use Swoole\Event;
use Swoole\Process;
use Swoole\Timer;

swoole_async_set(['enable_kqueue' => true]);

$timerId = Timer::after(1200, static function (): void {
    echo "timer expired\n";
});
$count = 0;
$raise = static fn () => Process::kill(getmypid(), SIGCHLD);

// SIGCHLD uses sigaction even when the I/O reactor uses kqueue.
Process::signal(SIGCHLD, static function () use (&$count, $raise, $timerId): void {
    echo 'SIGCHLD #', ++$count, PHP_EOL;
    if ($count === 1) {
        $raise();
        return;
    }

    Process::signal(SIGCHLD, null);
    if (Timer::exists($timerId)) {
        Timer::clear($timerId);
    }
});
Timer::after(10, $raise);
Event::wait();
?>
--EXPECT--
SIGCHLD #1
SIGCHLD #2
