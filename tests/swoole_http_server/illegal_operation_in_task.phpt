--TEST--
swoole_http_server: use coroutine in task without creating
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    echo curlGet("http://127.0.0.1:{$pm->getFreePort()}");
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), mt_rand(0, 1) ? SWOOLE_BASE : SWOOLE_PROCESS);
    $server->set([
        // 'log_file' => '/dev/null',
        'log_level' => SWOOLE_LOG_ERROR,
        'worker_num' => 1,
        'task_worker_num' => 1
    ]);
    $server->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($server) {
        $server->taskCo(['test'], 0.1);
    });
    $server->on('task', function (swoole_http_server $server, int $task_id, int $worker_id, string $data) use ($pm) {
        Swoole\Runtime::enableCoroutine();
        // wrong usage, you must create coroutine here: go(function(){ your_code_here });
        $pdo = new PDO(
            "mysql:host=" . MYSQL_SERVER_HOST . ";dbname=" . MYSQL_SERVER_DB . ";charset=utf8",
            MYSQL_SERVER_USER, MYSQL_SERVER_PWD
        );
        $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
        $query = $pdo->prepare('select * from userinfo LIMIT 1');
        $query->execute();
    });
    $server->on('finish', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	ERROR	Socket::yield() must be called in the coroutine.
