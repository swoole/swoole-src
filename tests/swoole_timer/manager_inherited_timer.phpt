--TEST--
swoole_timer: manager clears pre-start timers and can create its own timers
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_extension_not_exist('pcntl');
?>
--FILE--
<?php
use Swoole\Atomic;
use Swoole\Process;
use Swoole\Server;
use Swoole\Timer;

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $inherited = new Atomic();
    $unexpected = new Atomic();
    $masterTimer = new Atomic();
    $managerTimer = new Atomic();
    $process = new Process(function () use ($mode, $inherited, $unexpected, $masterTimer, $managerTimer) {
        $server = new Server('127.0.0.1', 0, $mode);
        $server->set(['worker_num' => 2, 'log_file' => '/dev/null']);
        $server->on('Receive', function () {});
        $server->on('ManagerStart', function ($server) use ($mode, $inherited, $masterTimer, $managerTimer) {
            $inherited->set(Timer::stats()['num']);
            Timer::tick(40, function ($id) use ($server, $mode, $masterTimer, $managerTimer) {
                if ($mode === SWOOLE_PROCESS && $masterTimer->get() === 0) {
                    return;
                }
                $managerTimer->add();
                Timer::clear($id);
                $server->shutdown();
            });
        });

        // With a Server object and no reactor, this creates a system timer.
        Timer::tick(20, function ($id) use ($server, $mode, $unexpected, $masterTimer) {
            if ($mode === SWOOLE_PROCESS && getmypid() === $server->master_pid) {
                $masterTimer->add();
                Timer::clear($id);
            } else {
                $unexpected->add();
            }
        });
        $server->start();
    }, false, 0);
    $pid = $process->start();
    $deadline = microtime(true) + 5;
    do {
        $waited = pcntl_waitpid($pid, $status, WNOHANG);
        if ($waited === $pid) {
            break;
        }
        usleep(10000);
    } while (microtime(true) < $deadline);
    $finished = $waited === $pid;
    if (!$finished) {
        Process::kill($pid, SIGTERM);
        do {
            $waited = pcntl_waitpid($pid, $status);
        } while ($waited === -1 && pcntl_get_last_error() === PCNTL_EINTR);
    }

    $result = [
        'mode' => $mode,
        'finished' => $finished,
        'exit_ok' => $waited === $pid && pcntl_wifexited($status) && pcntl_wexitstatus($status) === 0,
        'inherited' => $inherited->get(),
        'unexpected' => $unexpected->get(),
        'master_timer' => $masterTimer->get(),
        'manager_timer' => $managerTimer->get(),
    ];
    if (!$result['finished'] || !$result['exit_ok'] || $result['inherited'] !== 0 || $result['unexpected'] !== 0
        || $result['master_timer'] !== ($mode === SWOOLE_PROCESS ? 1 : 0) || $result['manager_timer'] !== 1) {
        throw new RuntimeException(json_encode($result));
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
