--TEST--
swoole_server: unregistered signal
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
        Assert::true(Swoole\Process::kill($pid, SIGPIPE));
        $deadline = microtime(true) + 2;
        do {
            clearstatcache(true, $logFile);
            $log = is_file($logFile) ? file_get_contents($logFile) : '';
            if (str_contains($log, '(ERRNO 721)')) {
                break;
            }
            usleep(1000);
        } while (microtime(true) < $deadline);
        Assert::contains($log, '(ERRNO 721)');
        echo $log, "\n";
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
[%s]	WARNING	%s (ERRNO 721): Unable to find callback function for signal Broken pipe: 13
