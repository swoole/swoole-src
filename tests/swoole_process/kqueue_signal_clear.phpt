--TEST--
swoole_process: clear inherited kqueue and native signal handlers after fork
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_darwin();
skip_if_extension_not_exist('pcntl');
?>
--FILE--
<?php
swoole_async_set(['enable_kqueue' => true]);

function checkInheritedSignal(): void
{
    $process = new Swoole\Process(function () {
        // The child must have the default disposition, even if its parent used
        // SIG_IGN for kqueue or a native manager signal handler.
        Swoole\Process::kill(getmypid(), SIGUSR1);
    }, false, 0);
    $pid = $process->start();
    do {
        $waited = pcntl_waitpid($pid, $status);
    } while ($waited === -1 && pcntl_get_last_error() === PCNTL_EINTR);
    var_dump($waited === $pid && pcntl_wifsignaled($status) && pcntl_wtermsig($status) === SIGUSR1);
}

// fork() destroys the inherited reactor before clearing its signal registrations.
$received = false;
Swoole\Process::signal(SIGUSR1, function () use (&$received) {
    $received = true;
    Swoole\Process::signal(SIGUSR1, null);
});
checkInheritedSignal();
Swoole\Timer::after(10, function () {});
Swoole\Process::kill(getmypid(), SIGUSR1);
Swoole\Event::wait();
var_dump($received);

?>
--EXPECT--
bool(true)
bool(true)
