<?php

use Swoole\Atomic;
use Swoole\Process;
use Swoole\Server;
use SwooleTest\ProcessManager;

$starts = [new Atomic(), new Atomic(), new Atomic()];
$pids = [new Atomic(), new Atomic(), new Atomic()];
$ready = new Atomic();
$errors = new Atomic();
$forced = new Atomic();
$after = new Atomic();
$pm = new ProcessManager();
$pm->setWaitTimeout(10);
$pm->parentFunc = function ($pid) use ($pm, $starts, $forced, $after, $errors) {
    $sent = Process::kill($pid, SIGUSR1);
    $deadline = microtime(true) + 10;
    do {
        $complete = $after->get() === 1 && $starts[0]->get() === 2
            && $starts[1]->get() === 2 && $starts[2]->get() === 2;
        if ($complete) {
            break;
        }
        usleep(1000);
    } while (microtime(true) < $deadline);
    $pm->kill();
    Assert::true($sent);
    Assert::true($complete);
    Assert::same($forced->get(), 3);
    Assert::same($errors->get(), 0);
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $mode, $starts, $pids, $ready, $errors, $forced, $after) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
    $server->set([
        'worker_num' => 3,
        'reload_async' => false,
        'max_wait_time' => 1,
        'enable_coroutine' => false,
        'log_file' => '/dev/null',
    ]);
    $server->on('Receive', function () {});
    $server->on('WorkerStart', function ($server, $id) use ($pm, $starts, $pids, $ready) {
        $pids[$id]->set(getmypid());
        if ($starts[$id]->add() !== 1) {
            return;
        }
        if ($ready->add() === 3) {
            $pm->wakeup();
        }
        // Block before entering the event loop: only the manager's timeout can stop this worker.
        while (true) {
            sleep(100);
        }
    });
    $server->on('WorkerError', function ($server, $id, $pid, $exitCode, $signal) use ($starts, $pids, $errors, $forced) {
        if ($exitCode !== 0 || $signal !== SIGKILL || $id !== $forced->get()) {
            $errors->add();
        }
        $forced->add();
        for ($next = $id + 1; $next < 3; $next++) {
            if ($starts[$next]->get() !== 1 || !Process::kill($pids[$next]->get(), 0)) {
                $errors->add();
            }
        }
    });
    $server->on('AfterReload', function () use ($after) {
        $after->add();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
