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
            $cli->setDefer(true);
            $cli->get('/');
        }
        foreach ($cli_map as $cli) {
            Assert::assert($cli->recv());
            Assert::same($cli->body, $pm->getRandomData());
        }

        $pm->kill();
        $pm->wait();

        // disable reconnect so we will get the first reason (conn was closed by server side)
        foreach ($cli_map as $cli) {
            $cli->set(['reconnect' => false]);
            $cli->setDefer(false);
            Assert::assert(!$cli->get('/'));
            Assert::same($cli->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
            Assert::same($cli->errCode, SOCKET_ECONNRESET);
        }

        // when we enable reconnect, we will get connect error
        foreach ($cli_map as $cli) {
            $cli->set(['reconnect' => true]);
            Assert::assert(!$cli->get('/'));
            Assert::same($cli->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
            Assert::same($cli->errCode, SOCKET_ECONNREFUSED);
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
    $server->on('shutdown', function (swoole_http_server $server) use ($pm) {
        foreach ($server->connections as $fd) {
            $server->close($fd);
        }
        $pm->wakeup();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
