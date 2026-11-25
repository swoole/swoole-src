--TEST--
swoole_server/task: cancellation lets a draining worker exit and a late large result is cleaned up (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$generation = new Swoole\Atomic;
$oldPid = new Swoole\Atomic;
$stopped = new Swoole\Atomic;
$release = new Swoole\Atomic;
$finished = new Swoole\Atomic;
$releaseStop = new Swoole\Atomic;
$tmpdir = sys_get_temp_dir() . '/swoole-6139-cancel-' . getmypid();
Assert::true(mkdir($tmpdir, 0700));
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $oldPid, $stopped, $release, $finished, $tmpdir, $releaseStop) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    $client->send("run\n");
    $pid = (int) trim($client->recv());
    $oldPid->set($pid);
    Assert::true(Swoole\Process::kill($pid, SIGTERM));
    Assert::same(trim($client->recv()), 'CANCELLED');
    $deadline = microtime(true) + 5;
    while (!$stopped->get() && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($stopped->get(), 1);
    // The result reaches the replacement only after its original owner has exited.
    $release->set(1);
    $deadline = microtime(true) + 5;
    while ((!$finished->get() || glob($tmpdir . '/*')) && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($finished->get(), 1);
    Assert::same(glob($tmpdir . '/*'), []);
    $releaseStop->set(1);
    $client->close();
    $probe = new Swoole\Client(SWOOLE_SOCK_TCP);
    Assert::true($probe->connect('127.0.0.1', $pm->getFreePort(), 5));
    $probe->send("ping\n");
    Assert::notSame((int) trim($probe->recv()), $pid);
    $probe->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $oldPid, $stopped, $release, $finished, $tmpdir, $releaseStop) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1, 'task_worker_num' => 1, 'enable_coroutine' => true,
        'reload_async' => true, 'max_wait_time' => 8, 'log_file' => '/dev/null',
        'open_eof_check' => true, 'package_eof' => "\n", 'task_tmpdir' => $tmpdir,
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm, $generation) {
        if ($id === 0 && $generation->add(1) === 1) {
            $pm->wakeup();
        }
    });
    $server->on('workerStop', function () use ($oldPid, $stopped, $releaseStop) {
        if (getmypid() === $oldPid->get()) {
            $stopped->set(1);
            // Keep WorkerStop running: the result socket must already be closed.
            $deadline = microtime(true) + 5;
            while (!$releaseStop->get() && microtime(true) < $deadline) {
                usleep(1000);
            }
        }
    });
    $server->on('receive', function ($server, $fd, $rid, $data) use ($generation) {
        if (trim($data) === 'ping') {
            $server->send($fd, getmypid() . "\n");
            return;
        }
        $server->send($fd, getmypid() . "\n");
        while ($generation->get() < 2) {
            Co::sleep(0.001);
        }
        $cancelled = false;
        $cid = go(function () use ($server, &$cancelled) {
            Assert::same($server->taskCo(['slow' => 'large'], 5), ['slow' => false]);
            Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
            $cancelled = true;
        });
        Assert::true(Co::cancel($cid));
        Assert::true($cancelled);
        $server->send($fd, "CANCELLED\n");
    });
    $server->on('task', function ($server, $id, $source, $data) use ($release, $finished) {
        $deadline = microtime(true) + 5;
        while (!$release->get() && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::true($server->finish(str_repeat('L', 16384)));
        $finished->set(1);
    });
    $server->on('finish', function () {});
    $server->start();
};
$pm->childFirst();
$pm->run();
Assert::true(rmdir($tmpdir));
echo "DONE\n";
?>
--EXPECT--
DONE
