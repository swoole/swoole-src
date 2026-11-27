--TEST--
swoole_server: SIGPIPE is ignored without unregistered-signal warning
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
//skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$logFile = __DIR__ . '/unregistered-signal-' . getmypid() . '.log';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $logFile) {
    try {
        // SIGPIPE is registered as SIG_IGN in master/worker (see commit 65f63b3f1),
        // so it is discarded by the kernel and must not log an unregistered-signal warning.
        Assert::true(Swoole\Process::kill($pid, SIGPIPE));
        usleep(100000);
        Assert::true(posix_kill($pid, 0), 'server should survive SIGPIPE');
        clearstatcache(true, $logFile);
        $log = is_file($logFile) ? file_get_contents($logFile) : '';
        Assert::false(str_contains($log, 'ERRNO 721'), 'SIGPIPE must not log an unregistered-signal warning');
        echo "DONE\n";
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm, $logFile) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => $logFile,
        'worker_num' => 1,
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function (Swoole\Server $server, $fd, $reactorId, $data) {
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
@unlink($logFile);
?>
--EXPECTF--
DONE
