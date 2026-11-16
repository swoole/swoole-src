--TEST--
swoole_server/task: taskCo with string keys
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../../include/bootstrap.php';

foreach ([false, true] as $enableCoroutine) {
    $pm             = new SwooleTest\ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 10));
        $client->send('run');
        Assert::same($client->recv(), 'OK');
        $client->close();
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $enableCoroutine) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
        $server->set([
            'worker_num'       => 1,
            'task_worker_num'  => 2,
            'enable_coroutine' => $enableCoroutine,
            'log_file'         => '/dev/null',
        ]);
        $server->on('workerStart', function ($server, $id) use ($pm) {
            if ($id === 0) {
                $pm->wakeup();
            }
        });
        $server->on('receive', function ($server, $fd) {
            $cases = [
                ['a' => 'foo', 'b' => 'bar'],
                [3       => 'foo', 7 => 'bar'],
                ['first' => 'foo', 4 => 'bar', -2 => 'baz', '01' => 'qux'],
                [1       => 'foo', 0 => 'bar'],
                ['slow', 'fast'],
                ['' => 'foo', PHP_INT_MAX => 'bar'],
            ];
            foreach ($cases as $tasks) {
                $before  = $tasks;
                $results = $server->taskCo($tasks, 5);
                Assert::isArray($results);
                Assert::same($tasks, $before);
                $expected = [];
                foreach ($tasks as $key => $task) {
                    $expected[$key] = 'done: ' . $task;
                }
                Assert::same($results, $expected);
            }
            $server->send($fd, 'OK');
        });
        $server->on('task', function ($server, $id, $source, $data) {
            if ($data === 'slow') {
                usleep(100000);
            }
            return "done: {$data}";
        });
        $server->on('finish', function () {});
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
