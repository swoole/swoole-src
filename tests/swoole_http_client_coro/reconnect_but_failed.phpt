--TEST--
swoole_http_client_coro: reconnect but failed
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

        for ($n = MAX_REQUESTS; $n--;) {
            $ret = $cli->get('/');
            Assert::eq($ret, !($n % 2));
            if ($ret) {
                Assert::eq($cli->body, $pm->getRandomData());
            }
        }

        $pm->kill();
        usleep(1000);

        assert(!$cli->get('/'));
        Assert::eq($cli->errCode, SOCKET_ECONNRESET);
        Assert::eq($cli->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
        for ($n = MAX_REQUESTS; $n--;) {
            assert(!$cli->get('/'));
            Assert::eq($cli->errCode, SOCKET_ECONNREFUSED);
            Assert::eq($cli->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
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
        if ($i % 2) {
            $server->close($request->fd);
        } else {
            $response->end($pm->getRandomData());
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
