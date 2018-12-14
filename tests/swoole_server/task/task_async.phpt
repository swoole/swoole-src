--TEST--
swoole_runtime: pdo in task and http response detach
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_pdo_not_support_mysql8();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    for ($i = MAX_CONCURRENCY_LOW; $i--;) {
        go(function () use ($pm) {
            $ret = httpCoroGet("http://127.0.0.1:{$pm->getFreePort()}");
            assert($ret === 'Hello Swoole!');
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
        'task_async' => true
    ]);
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($http) {
        assert($response->detach());
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
    $http->on('task', function (swoole_http_server $server, $taskId, $srcWorkerId, $fd) {
        if (mt_rand(0, 1)) {
            return [$fd, 'Hello Swoole!'];
        } else {
            $response = swoole_http_response::create($fd);
            go(function () use ($response) {
                $pdo = new PDO(
                    "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
                    MYSQL_SERVER_USER, MYSQL_SERVER_PWD
                );
                $stmt = $pdo->query('SELECT "Hello Swoole!"');
                assert($stmt->execute());
                $ret = $stmt->fetchAll(PDO::FETCH_COLUMN)[0];
                $response->end($ret);
            });
            return null;
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
