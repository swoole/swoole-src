--TEST--
swoole_server/task: taskCo and taskWaitMulti share timeout results inside and outside coroutines
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../../include/bootstrap.php';

foreach ([false, true] as $enableCoroutine) {
    foreach (['taskCo', 'taskWaitMulti'] as $method) {
        $gate           = new Swoole\Atomic();
        $completed      = new Swoole\Atomic();
        $pm             = new ProcessManager();
        $pm->parentFunc = function () use ($pm) {
            $client = new Swoole\Client(SWOOLE_SOCK_TCP);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 10));
            $client->send('run');
            Assert::same($client->recv(), 'OK');
            $client->close();
            $pm->kill();
        };
        $pm->childFunc = function () use ($pm, $enableCoroutine, $method, $gate, $completed) {
            $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
            $server->set([
                'worker_num'       => 1,
                'task_worker_num'  => 2,
                'enable_coroutine' => $enableCoroutine,
                'log_file'         => '/dev/null',
            ]);
            $server->on('WorkerStart', function ($server, $id) use ($pm) {
                if ($id === 0) {
                    $pm->wakeup();
                }
            });
            $server->on('Receive', function ($server, $fd) use ($enableCoroutine, $method, $gate, $completed) {
                Assert::same($server->{$method}([]), false);
                Assert::same(swoole_last_error(), SWOOLE_ERROR_TASK_DISPATCH_FAIL);
                Assert::false(@$server->$method(range(1, 1024), 5));
                try {
                    $server->{$method}('not an array');
                    Assert::true(false);
                } catch (TypeError $e) {
                    Assert::contains($e->getMessage(), 'must be of type array');
                }
                $waitFor = function ($count) use ($enableCoroutine, $completed) {
                    $deadline = microtime(true) + 5;
                    while ($completed->get() < $count && microtime(true) < $deadline) {
                        if ($enableCoroutine) {
                            Co::sleep(0.001);
                        } else {
                            usleep(1000);
                        }
                    }
                    Assert::same($completed->get(), $count);
                };
                Assert::same($server->{$method}(['slow' => 'slow', 3 => 'fast'], 0.5), [
                    'slow' => false,
                    3      => 'done:fast',
                ]);
                Assert::same(swoole_last_error(), SWOOLE_ERROR_TASK_TIMEOUT);
                $gate->set(1);
                $waitFor(2);

                $gate->set(0);
                Assert::same($server->{$method}(['only' => 'slow'], 0.5), ['only' => false]);
                Assert::same(swoole_last_error(), SWOOLE_ERROR_TASK_TIMEOUT);
                $gate->set(1);
                $waitFor(3);
                Assert::same($server->{$method}(['recovered' => 'fast'], 5), ['recovered' => 'done:fast']);
                Assert::same(swoole_last_error(), 0);
                $server->send($fd, 'OK');
            });
            $server->on('Task', function ($server, $id, $source, $data) use ($gate, $completed) {
                $deadline = microtime(true) + 10;
                while ($data === 'slow' && !$gate->get() && microtime(true) < $deadline) {
                    usleep(1000);
                }
                $completed->add();
                return 'done:' . $data;
            });
            $server->on('Finish', function () {});
            $server->start();
        };
        $pm->childFirst();
        $pm->run();
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
