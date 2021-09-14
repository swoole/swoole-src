--TEST--
swoole_server/task: task_co
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
$pm = new SwooleTest\ProcessManager;

$randoms = [];
for ($n = MAX_REQUESTS; $n--;) {
    $randoms[] = random_bytes(mt_rand(0, 65536));
}

$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        for ($n = MAX_REQUESTS; $n--;) {
            if (!Assert::assert(($res = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/task?n={$n}")) === 'OK')) {
                echo "{$res}\n";
                break;
            }
        }
    });
    Swoole\Event::wait();
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $randoms) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => '/dev/null',
        'worker_num' => 4,
        'task_worker_num' => 4,
        'task_enable_coroutine' => true
    ]);
    $server->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request',
        function (swoole_http_request $request, swoole_http_response $response) use ($server, $randoms) {
            $n = $request->get['n'];
            switch ($request->server['path_info']) {
                case '/task':
                {
                    list($ret_n, $ret_random) = $server->taskCo([$n], 1)[0];
                    if ($ret_n !== $n) {
                        $response->end("ERROR MATCH {$ret_n} with {$n}");
                        return;
                    } elseif ($ret_random !== $randoms[$n]) {
                        $response->end("ERROR EQUAL {$ret_n}(" . strlen($ret_random) . ") with {$n}(" . strlen($randoms[$n]) . ")");
                        return;
                    }
                    $response->end('OK');
                    break;
                }
                case '/random':
                {
                    $response->end($randoms[$n]);
                    break;
                }
            }
        });
    $server->on('task', function (swoole_http_server $server, swoole_server_task $task) use ($pm) {
        $task->finish([$task->data, httpGetBody('http://127.0.0.1:' . $pm->getFreePort() . "/random?n={$task->data}")]);
    });
    $server->on('finish', function () {
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
