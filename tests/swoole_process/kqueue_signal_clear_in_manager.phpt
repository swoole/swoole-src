--TEST--
swoole_process: clear native manager signal handlers after fork with kqueue enabled
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_darwin();
skip_if_extension_not_exist('pcntl');
?>
--FILE--
<?php
swoole_async_set(['enable_kqueue' => true]);

$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE);
$server->set(['worker_num' => 2, 'log_file' => '/dev/null']);
$server->on('Receive', function () {});
$server->on('ManagerStart', function ($server) {
    // The manager has native signal handlers and no reactor, even with kqueue enabled.
    $process = new Swoole\Process(function () {
        Swoole\Process::kill(getmypid(), SIGUSR1);
    }, false, 0);
    $pid = $process->start();
    do {
        $waited = pcntl_waitpid($pid, $status);
    } while ($waited === -1 && pcntl_get_last_error() === PCNTL_EINTR);
    var_dump($waited === $pid && pcntl_wifsignaled($status) && pcntl_wtermsig($status) === SIGUSR1);
    $server->shutdown();
});
$server->start();
?>
--EXPECT--
bool(true)
