--TEST--
swoole_timer: a fatal error in a timer callback ends the server worker with exit code 255
--INI--
fatal_error_backtraces=0
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;

$atomic = new Atomic();
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $atomic) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('WorkerStart', function () use ($atomic) {
        if ($atomic->add() === 1) {
            Swoole\Timer::after(1, function () {
                throw new RuntimeException('timer failed');
            });
        }
    });
    $server->on('WorkerError', function ($server, $workerId, $workerPid, $exitCode, $signal) use ($pm) {
        echo "worker exited: code={$exitCode}, signal={$signal}\n";
        $pm->wakeup();
    });
    $server->on('Receive', function () {});
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: Uncaught RuntimeException: timer failed in %s:%d
Stack trace:
%A
worker exited: code=255, signal=0
DONE
