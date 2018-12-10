--TEST--
swoole_http_client_coro: error handler
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomData(MAX_CONCURRENCY_MID);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli_map = [];
        for ($c = MAX_CONCURRENCY_MID; $c--;) {
            $cli_map[] = $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => -1]);
            $cli->setDefer(true);
            $cli->get('/');
        }
        foreach ($cli_map as $cli) {
            assert($cli->recv());
            assert($cli->body === $pm->getRandomData());
        }

        $pm->kill();
        usleep(1000);

        // will get connection is reset by peer
        foreach ($cli_map as $cli) {
            $cli->get('/');
        }
        foreach ($cli_map as $cli) {
            assert(!$cli->recv());
            assert($cli->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
            assert($cli->errCode === SOCKET_ECONNRESET);
        }

        // if developer not hold the error and try again, he will get `connection is not available` error here.
        foreach ($cli_map as $cli) {
            assert(!$cli->get('/'));
        }
        foreach ($cli_map as $cli) {
            assert(!$cli->recv());
            assert($cli->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
            assert($cli->errCode === SWOOLE_ERROR_CLIENT_NO_CONNECTION);
        }

        // set defer to false, it will auto retry
        foreach ($cli_map as $cli) {
            $cli->setDefer(false);
            assert(!$cli->get('/'));
            assert($cli->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
            assert($cli->errCode === SOCKET_ECONNREFUSED, swoole_strerror($cli->errCode));
        }
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
        if ($i <= MAX_CONCURRENCY_MID) {
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
