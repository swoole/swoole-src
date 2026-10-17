--TEST--
swoole_server: reloaded workers do not inherit the manager's signal listeners
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;
use Swoole\Server;

foreach ([SWOOLE_BASE => 'BASE', SWOOLE_PROCESS => 'PROCESS'] as $mode => $name) {
    $process = new Process(function () use ($mode, $name) {
        $registered = new Atomic();
        $starts = new Atomic();
        $server = new Server('127.0.0.1', 0, $mode);
        $server->set(['worker_num' => 2, 'log_file' => '/dev/null']);
        $server->on('managerStart', function () use ($registered) {
            Process::signal(SIGINT, function () {});
            $registered->wakeup();
        });
        $server->on('workerStart', function (Server $server, int $workerId) use ($registered, $starts, $name) {
            if ($workerId !== 0) {
                return;
            }
            // the initial workers are forked before onManagerStart, the replacements after it
            if ($starts->add() === 1) {
                $registered->wait(-1);
                $server->reload();
                return;
            }
            go(function () {
                System::sleep(0.1);
                Process::kill(getmypid(), SIGUSR2);
            });
            Assert::same(System::waitSignal(SIGUSR2, 1), SIGUSR2);
            Assert::true(Process::signal(SIGINT, function () {}));
            Assert::same(Coroutine::stats()['signal_listener_num'], 1);
            Assert::true(Process::signal(SIGINT, null));
            echo "{$name}: DONE\n";
            $server->shutdown();
        });
        $server->on('receive', function () {});
        $server->start();
    });
    $process->start();
    Process::wait();
}
?>
--EXPECT--
BASE: DONE
PROCESS: DONE
