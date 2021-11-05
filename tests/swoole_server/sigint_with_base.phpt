--TEST--
swoole_server: register sigint handler with base mode
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Process;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    Process::kill($pid, SIGINT);
    usleep(10000);
    echo file_get_contents(TEST_LOG_FILE);
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
    ]);
    $server->on('workerStart', function (Server $server) use ($pm) {
        Process::signal(SIGINT, function () use ($server) {
            file_put_contents(TEST_LOG_FILE, 'SIGINT, SHUTDOWN' . PHP_EOL);
            $server->shutdown();
        });
        $pm->wakeup();
    });
    $server->on('Receive', function (Server $server, $fd, $reactorId, $data) {
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
@unlink(TEST_LOG_FILE);
?>
--EXPECT--
SIGINT, SHUTDOWN
