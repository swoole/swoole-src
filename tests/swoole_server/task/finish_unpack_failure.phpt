--TEST--
swoole_server/task: failed FINISH unpack settles coroutine waits and releases independent callbacks
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $finished = new Swoole\Atomic();
    $tmpdir = sys_get_temp_dir() . '/swoole-task-unpack-' . getmypid() . '-' . $mode;
    Assert::true(mkdir($tmpdir, 0700));
    $pm = new ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        Assert::same($client->send('run'), 3);
        Assert::same($client->recv(), 'OK');
        $client->close();
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode, $finished, $tmpdir) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'task_worker_num' => 1, 'task_tmpdir' => $tmpdir,
            'log_file' => '/dev/null']);
        $server->on('WorkerStart', function ($server) use ($pm) {
            if (!$server->taskworker) { $pm->wakeup(); }
        });
        $server->on('Task', function ($server, $id, $source, $data) use ($finished) {
            Assert::true($server->finish($data === 'large' ? str_repeat('x', 16384) : 'small'));
            $finished->add();
        });
        $server->on('Receive', function ($server, $fd) use ($finished, $tmpdir) {
            foreach ([0, 1, 2] as $case) {
                $before = $finished->get();
                $done = false;
                $called = false;
                $weak = null;
                if ($case < 2) {
                    $cid = go(function () use ($server, $case, &$done) {
                        if ($case === 0) {
                            Assert::false($server->taskwait('large', 10));
                        } else {
                            Assert::same($server->taskCo(['bad' => 'large', 'good' => 'small'], 10),
                                ['bad' => false, 'good' => 'small']);
                        }
                        $done = true;
                    });
                } else {
                    $owner = new stdClass();
                    $weak = WeakReference::create($owner);
                    $callback = function () use ($owner, &$called) { $called = true; };
                    Assert::greaterThanEq($server->task('large', -1, $callback), 0);
                    unset($owner, $callback);
                    Assert::notNull($weak->get());
                }
                // Block only this event worker until FINISH has been published. Delete its private
                // result file before returning to the loop, so onFinish deterministically fails to unpack.
                $deadline = microtime(true) + 5;
                $expected = $before + ($case === 1 ? 2 : 1);
                while ($finished->get() < $expected && microtime(true) < $deadline) { usleep(1000); }
                Assert::same($finished->get(), $expected);
                $files = glob($tmpdir . '/*');
                Assert::same(count($files), 1);
                Assert::true(unlink($files[0]));
                $deadline = microtime(true) + 2;
                while (($case < 2 ? !$done : $weak->get() !== null) && microtime(true) < $deadline) {
                    Swoole\Coroutine::sleep(0.001);
                }
                Assert::false($called);
                if ($case < 2) { Assert::true($done); }
                else { Assert::null($weak->get()); }
            }
            $server->send($fd, 'OK');
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
    Assert::same(glob($tmpdir . '/*'), []);
    Assert::true(rmdir($tmpdir));
}
echo "DONE\n";
?>
--EXPECT--
DONE
