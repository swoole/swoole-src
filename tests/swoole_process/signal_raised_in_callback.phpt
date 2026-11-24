--TEST--
swoole_process: a signal raised while a signal callback runs is dispatched
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Event;
use Swoole\Process;

// Linux defaults to signalfd; this covers the sigaction backend.
swoole_async_set(['enable_signalfd' => false]);

$usr1 = 0;
Process::signal(SIGUSR1, function () use (&$usr1) {
    echo 'USR1 #', ++$usr1, PHP_EOL;
    if ($usr1 === 1) {
        Process::kill(getmypid(), SIGUSR1);
        return;
    }
    Process::signal(SIGUSR1, null);
    Process::signal(SIGUSR2, null);
});
Process::signal(SIGUSR2, function () {
    echo 'USR2', PHP_EOL;
    Process::kill(getmypid(), SIGUSR1);
});
Event::defer(fn () => Process::kill(getmypid(), SIGUSR2));
Event::wait();
?>
--EXPECT--
USR2
USR1 #1
USR1 #2
