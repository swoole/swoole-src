--TEST--
swoole_client_sync: recv in task worker
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', 0, SWOOLE_BASE);
    $http->set(['worker_num' => 1, 'task_worker_num'=>1, 'log_file' => '/dev/null']);
    $http->on('workerStart', function (swoole_server $server, int $worker_id) use ($pm) {
        if (!$server->taskworker) {
            // start logic in task
            $server->task(1, 0);
        }
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($http) {
        usleep(100 * 1000);
        $response->end('OK');
    });
    $http->on('Task', function(swoole_server $serv, int $task_id, int $src_worker_id, $data) use ($pm) {
            //  trigger timer constantly in order to trigger the EINTR internally
            swoole_timer_tick(1, function(){});
            // send request
            $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
            $p = $serv->ports[0]->port;
            Assert::assert($cli->connect('127.0.0.1', $p, 3));
            $request = "GET / HTTP/1.1\r\n\r\n";
            $cli->send($request);
            $response = @$cli->recv(); // the server will block by 100ms, so it will surely get EINTR internally by the task timer
            if (!$response) {
                if ($cli->errCode == SOCKET_EINTR) {
                    echo "EINTR\n";
                }
            } else {
                echo "SUCCESS\n";
            }
            $pm->wakeup();
    });
    $http->on('Finish', function(){});
    $http->addProcess(new swoole_process(function (swoole_process $p) {
                }));
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
