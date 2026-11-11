--TEST--
swoole_server: a replacement worker receives CLOSE queued while the manager still publishes the dead worker PID
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Server;

$workerPid = new Atomic();
$starts = new Atomic();
$managerWaiting = new Atomic();
$allowRestart = new Atomic();
$closes = new Atomic();
$retired = new Atomic();
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm, $workerPid, $managerWaiting, $allowRestart, $closes, $retired) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 5);
    stream_set_timeout($client, 5);
    fwrite($client, 'begin');
    Assert::same(fgets($client), "ready\n");
    Assert::true(Swoole\Process::kill($workerPid->get(), SIGKILL));
    $deadline = microtime(true) + 5;
    while ($managerWaiting->get() === 0 && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($managerWaiting->get(), 1);
    Assert::true(stream_socket_shutdown($client, STREAM_SHUT_WR));
    Assert::same(stream_get_contents($client), '');
    Assert::false(stream_get_meta_data($client)['timed_out']);
    // Let the reactor's deferred check run while the dead PID is still published.
    usleep(1200000);
    Assert::same($closes->get(), 0);
    $allowRestart->set(1);
    $deadline = microtime(true) + 5;
    while (($closes->get() === 0 || $retired->get() === 0) && microtime(true) < $deadline) {
        usleep(10000);
    }
    Assert::same($closes->get(), 1);
    Assert::same($retired->get(), 1);
    fclose($client);
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $workerPid, $starts, $managerWaiting, $allowRestart, $closes, $retired) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'reactor_num' => 1,
        'enable_coroutine' => false,
        'heartbeat_check_interval' => 0,
        'max_wait_time' => 30,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function (Server $server) use ($pm, $workerPid, $starts, $retired) {
        $workerPid->set(getmypid());
        Swoole\Timer::tick(10, function () use ($server, $retired) {
            $retired->set($server->stats()['close_count']);
        });
        if ($starts->add() === 1) {
            $pm->wakeup();
        }
    });
    $server->on('workerError', function () use ($managerWaiting, $allowRestart) {
        $managerWaiting->set(1);
        $deadline = microtime(true) + 10;
        while ($allowRestart->get() === 0 && microtime(true) < $deadline) {
            usleep(1000);
        }
    });
    $server->on('workerExit', function () {
        Swoole\Timer::clearAll();
    });
    $server->on('receive', function (Server $server, int $fd) {
        Assert::true($server->send($fd, "ready\n"));
    });
    $server->on('close', function () use ($closes) {
        Assert::same($closes->add(), 1);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
