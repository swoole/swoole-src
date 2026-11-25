--TEST--
swoole_server/task: a forwarded large result after taskCo timeout is discarded and cleaned up (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$generation = new Swoole\Atomic;
$release = new Swoole\Atomic;
$finished = new Swoole\Atomic;
$tmpdir = sys_get_temp_dir() . '/swoole-6139-' . getmypid();
Assert::true(mkdir($tmpdir, 0700));
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $release, $finished, $tmpdir) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    $client->send("run\n");
    $pid = (int) trim($client->recv());
    Assert::true(Swoole\Process::kill($pid, SIGTERM));
    $deadline = microtime(true) + 5;
    while ($generation->get() < 2 && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($generation->get(), 2);
    Assert::same(trim($client->recv()), 'TIMEOUT');
    $release->set(1);
    Assert::same(trim($client->recv()), 'CLEAN');
    Assert::same($finished->get(), 1);
    Assert::same(glob($tmpdir . '/*'), []);
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $release, $finished, $tmpdir) {
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
    $server->on('receive', function ($server, $fd) use ($finished, $tmpdir) {
        $server->send($fd, getmypid() . "\n");
        Assert::same($server->taskCo(['slow' => 'large'], 0.2), ['slow' => false]);
        $server->send($fd, "TIMEOUT\n");
        // Keep an existing request alive while its expired result returns through
        // the replacement. No stack-owned TaskCo may be resumed a second time.
        $deadline = microtime(true) + 5;
        do {
            Co::sleep(0.001);
        } while ((!$finished->get() || glob($tmpdir . '/*')) && microtime(true) < $deadline);
        Assert::same($finished->get(), 1);
        Assert::same(glob($tmpdir . '/*'), []);
        $server->send($fd, "CLEAN\n");
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
