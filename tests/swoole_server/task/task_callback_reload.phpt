--TEST--
swoole_server/task: per-task callbacks keep their original worker alive and can submit more callbacks while draining (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

foreach ([false, true] as $eventObject) {
    $generation = new Swoole\Atomic;
    $started = new Swoole\Atomic;
    $release = new Swoole\Atomic;
    $oldPid = new Swoole\Atomic;
    $stopped = new Swoole\Atomic;
    $pm = new SwooleTest\ProcessManager;
    $pm->parentFunc = function () use ($pm, $generation, $started, $release, $oldPid, $stopped) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        $client->send("run\n");
        $pid = (int) trim($client->recv());
        $oldPid->set($pid);
        $deadline = microtime(true) + 5;
        while (!$started->get() && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($started->get(), 1);
        Assert::true(Swoole\Process::kill($pid, SIGTERM));
        $deadline = microtime(true) + 5;
        while ($generation->get() < 2 && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($generation->get(), 2);
        $release->set(1);
        Assert::same(json_decode(trim($client->recv()), true), ['pid' => $pid, 'callbacks' => 32]);
        $deadline = microtime(true) + 5;
        while (!$stopped->get() && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($stopped->get(), 1);
        $client->close();
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $generation, $started, $release, $oldPid, $stopped, $eventObject) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
        $server->set([
            'worker_num' => 1, 'task_worker_num' => 1, 'enable_coroutine' => true,
            'reload_async' => true, 'max_wait_time' => 8, 'log_file' => '/dev/null',
            'open_eof_check' => true, 'package_eof' => "\n", 'event_object' => $eventObject,
        ]);
        $server->on('workerStart', function ($server, $id) use ($pm, $generation) {
            if ($id === 0 && $generation->add(1) === 1) {
                $pm->wakeup();
            }
        });
        $server->on('workerStop', function () use ($oldPid, $stopped) {
            if (getmypid() === $oldPid->get()) {
                $stopped->set(1);
            }
        });
        $server->on('receive', function ($server, $fd) use ($eventObject) {
            $fd = $eventObject ? $fd->fd : $fd;
            $pid = getmypid();
            $server->send($fd, "$pid\n");
            Assert::integer($server->task('first', -1, function ($server, $id, $data = null) use ($fd, $pid, $eventObject) {
                $data = $eventObject ? $id->data : $data;
                Assert::same(getmypid(), $pid);
                Assert::same($data, str_repeat('L', 16384));
                $remaining = 32;
                // Grow and rehash task_callbacks while its first callback is running.
                for ($i = 0; $i < 32; $i++) {
                    Assert::integer($server->task('nested', -1, function ($server, $id, $data = null) use ($fd, $pid, &$remaining, $eventObject) {
                        $data = $eventObject ? $id->data : $data;
                        Assert::same(getmypid(), $pid);
                        Assert::same($data, 'nested');
                        if (--$remaining === 0) {
                            $server->send($fd, json_encode(['pid' => getmypid(), 'callbacks' => 32]) . "\n");
                        }
                    }));
                }
            }));
            // No coroutine wait or timer keeps this request alive; only the callback does.
        });
        $server->on('task', function ($server, $id, $source = null, $data = null) use ($started, $release, $eventObject) {
            $data = $eventObject ? $id->data : $data;
            if ($data === 'first') {
                $started->set(1);
                $deadline = microtime(true) + 5;
                while (!$release->get() && microtime(true) < $deadline) {
                    usleep(1000);
                }
                Assert::true($server->finish(str_repeat('L', 16384)));
                // An already consumed callback must not decrement the count twice.
                Assert::true($server->finish('duplicate'));
                return;
            }
            return $data;
        });
        if (!$eventObject) {
            $server->on('finish', function () { Assert::true(false, 'per-task callback reached global onFinish'); });
        }
        // Object callbacks intentionally run without a global onFinish handler.
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
