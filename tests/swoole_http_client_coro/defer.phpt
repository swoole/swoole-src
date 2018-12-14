--TEST--
swoole_http_client_coro: error handler
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomData(MAX_REQUESTS);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 1]);

        // normal
        for ($n = MAX_REQUESTS; $n--;) {
            assert($cli->get('/'));
            assert($cli->body === $pm->getRandomData());
        }

        // failed when recv response
        $retry_time = microtime(true);
        for ($n = MAX_REQUESTS; $n--;) {
            assert(!$cli->get('/'));
        }
        $retry_time = microtime(true) - $retry_time;

        $pm->kill();
        usleep(1000);

        // failed when connect
        $failed_time = microtime(true);
        for ($n = MAX_REQUESTS; $n--;) {
            assert(!$cli->get('/'));
            assert($cli->errCode === SOCKET_ECONNREFUSED);
            assert($cli->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED, $cli->statusCode);
        }
        $failed_time = microtime(true) - $failed_time;

        assert($retry_time > $failed_time * 2);
    });
    swoole_event_wait();
    echo "OK\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($pm, $server) {
        static $i = 0;
        $i++;
        if ($i <= MAX_REQUESTS) {
            co::sleep(0.1 / MAX_REQUESTS);
            $response->end($pm->getRandomData());
        } else {
            $server->close($request->fd);
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
