--TEST--
swoole_server/task: reclaim an idle forwarding socket after twice max_wait_time (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_linux();
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

function socketInodes(int $pid): array
{
    $sockets = [];
    foreach (glob("/proc/$pid/fd/*") as $fd) {
        $target = @readlink($fd);
        if (is_string($target) && str_starts_with($target, 'socket:[')) {
            $sockets[] = $target;
        }
    }
    return $sockets;
}

$generation = new Swoole\Atomic;
$currentPid = new Swoole\Atomic;
$started = new Swoole\Atomic;
$release = new Swoole\Atomic;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $currentPid, $started, $release) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    $client->send("run\n");
    $oldPid = (int) trim($client->recv());
    $deadline = microtime(true) + 5;
    while (!$started->get() && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($started->get(), 1);
    Assert::true(Swoole\Process::kill($oldPid, SIGTERM));
    $deadline = microtime(true) + 5;
    while ($generation->get() < 2 && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($generation->get(), 2);
    $pid = $currentPid->get();
    $before = socketInodes($pid);
    $release->set(1);
    Assert::same(trim($client->recv()), 'OK');
    $cached = array_values(array_diff(socketInodes($pid), $before));
    Assert::count($cached, 1);
    // No further request or task result arrives. Timer expiry must close the
    // kernel socket itself, rather than waiting for another send or worker exit.
    $deadline = microtime(true) + 5;
    do {
        usleep(10000);
        $remaining = array_values(array_intersect($cached, socketInodes($pid)));
    } while ($remaining && microtime(true) < $deadline);
    Assert::same($remaining, []);
    Assert::true(Swoole\Process::kill($pid, 0));
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $currentPid, $started, $release) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1, 'task_worker_num' => 1, 'enable_coroutine' => true,
        'reload_async' => true, 'max_wait_time' => 1, 'log_file' => '/dev/null',
        'open_eof_check' => true, 'package_eof' => "\n",
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm, $generation, $currentPid) {
        if ($id === 0) {
            $currentPid->set(getmypid());
            if ($generation->add(1) === 1) {
                $pm->wakeup();
            }
        }
    });
    $server->on('receive', function ($server, $fd) {
        $server->send($fd, getmypid() . "\n");
        Assert::integer($server->task('work', -1, function ($server) use ($fd) {
            $server->send($fd, "OK\n");
        }));
    });
    $server->on('task', function ($server, $id, $source, $data) use ($started, $release) {
        $started->set(1);
        $deadline = microtime(true) + 5;
        while (!$release->get() && microtime(true) < $deadline) {
            usleep(1000);
        }
        return 'done';
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
