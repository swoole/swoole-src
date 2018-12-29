--TEST--
swoole_server: unregistered signal
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $pid = file_get_contents(TEST_PID_FILE);
    usleep(1000);
    Swoole\Process::kill($pid, SIGPIPE);
    usleep(1000);
    $log = file_get_contents(TEST_LOG_FILE);
    echo $log, "\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    @unlink(TEST_LOG_FILE);
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set([
        'log_file' => TEST_LOG_FILE,
        'pid_file' => TEST_PID_FILE
    ]);
    $server->on('WorkerStart', function (Swoole\Server $server, $worker_id) use ($pm) { $pm->wakeup(); });
    $server->on('Receive', function (Swoole\Server $server, $fd, $reactorId, $data) { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	WARNING	%s (ERROR 707): Unable to find callback function for signal Broken pipe: 13.
