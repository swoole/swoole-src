--TEST--
swoole_server: register sigint handler with base mode
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    Swoole\Process::kill($pid, SIGINT);
    usleep(10000);
    echo file_get_contents(TEST_LOG_FILE);
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
    ]);
    $server->on('workerStart', function (Swoole\Server $server) use ($pm) {
        $pm->wakeup();
        \Swoole\Process::signal(2, function () use ($server) {
            file_put_contents(TEST_LOG_FILE, 'SIGINT, SHUTDOWN' . PHP_EOL);
            $server->shutdown();
        });
    });
    $server->on('Receive', function (Swoole\Server $server, $fd, $reactorId, $data) {
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
@unlink(TEST_LOG_FILE);
?>
--EXPECT--
SIGINT, SHUTDOWN
