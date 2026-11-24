--TEST--
swoole_server/base: exit() in a process after its single-worker server stops
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Process;
use Swoole\Server;

$process = new Process(function () {
    $server = new Server('127.0.0.1', get_one_free_port(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'enable_coroutine' => false,
        'reload_async' => false,
    ]);
    $server->on('WorkerStart', function (Server $server) {
        Swoole\Timer::after(100, fn () => $server->shutdown());
    });
    $server->on('Receive', function () {});
    $server->start();
    echo "STOPPED\n";
    exit(4);
});
$process->start();
$status = Process::wait();
echo "code={$status['code']}, signal={$status['signal']}\n";
?>
--EXPECT--
STOPPED
code=4, signal=0
