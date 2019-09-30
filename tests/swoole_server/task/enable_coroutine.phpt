--TEST--
swoole_server/task: task [enable_coroutine]
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
$pm = new SwooleTest\ProcessManager;

$randoms = [];
for ($n = MAX_REQUESTS; $n--;)
{
    $randoms[] = random_bytes(mt_rand(0, 65536));
}

$pm->parentFunc = function ($pid) use ($pm) {
    for ($n = MAX_REQUESTS; $n--;) {
        go(function () use ($pm, $n) {
            $c = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $c->set(['timeout' => 5,]);
            Assert::assert($c->get('/task?n='.$n));
            Assert::same($c->body, "OK");
        });
    }
    swoole_event_wait();
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $randoms) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
        'task_worker_num' => 1,
        'task_enable_coroutine' => true,
    ]);
    $server->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($server, $randoms) {
        $n = $request->get['n'];
        list($ret_n, $ret_random) = $server->taskwait($n, 1);
        if ($ret_n !== $n) {
            $response->end("ERROR MATCH {$ret_n} with {$n}");
            return;
        } elseif ($ret_random !== $randoms[$n]) {
            $response->end("ERROR EQUAL {$ret_n}(" . strlen($ret_random) . ") with {$n}(" . strlen($randoms[$n]) . ")");
            return;
        }
        $response->end('OK');
    });
    $server->on('task', function (swoole_http_server $server, Swoole\Server\Task $task) use ($pm, $randoms) {
        Assert::same($task->worker_id, 0);
        Assert::assert($task->flags > 0);
        Assert::assert($task->id >= 0);
        $n = $task->data;
        co::sleep(0.002);
        $task->finish([$n, $randoms[$n]]);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
