--TEST--
swoole_server/task: pdo in task and http response detach
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_pdo_not_support_mysql8();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    for ($i = MAX_CONCURRENCY_LOW; $i--;) {
        go(function () use ($pm) {
            $ret = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}");
            Assert::same($ret, 'Hello Swoole!');
        });
    }
    swoole_event_wait();
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $http->set([
        'log_file' => '/dev/null',
        'task_worker_num' => 4,
        'task_enable_coroutine' => true
    ]);
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($http) {
        Assert::assert($response->detach());
        if (mt_rand(0, 1)) {
            $http->task($response->fd);
        } else {
            $http->task($response->fd, -1, function ($server, $taskId, $data) {
                list($fd, $data) = $data;
                $response = swoole_http_response::create($fd);
                $response->end($data);
            });
        }
    });
    $http->on('task', function (swoole_http_server $server, swoole_server_task $task) {
        $fd = $task->data;
        if (mt_rand(0, 1)) {
            $task->finish([$fd, 'Hello Swoole!']);
        } else {
            $response = swoole_http_response::create($fd);
            $pdo = new PDO(
                "mysql:host=" . MYSQL_SERVER_HOST . ";port=" . MYSQL_SERVER_PORT . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
                MYSQL_SERVER_USER, MYSQL_SERVER_PWD
            );
            $stmt = $pdo->query('SELECT "Hello Swoole!"');
            Assert::assert($stmt->execute());
            $ret = $stmt->fetchAll(PDO::FETCH_COLUMN)[0];
            $response->end($ret);
        }
    });
    $http->on('finish', function ($server, $taskId, $data) {
        list($fd, $ret) = $data;
        $response = swoole_http_response::create($fd);
        $response->end($ret);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
