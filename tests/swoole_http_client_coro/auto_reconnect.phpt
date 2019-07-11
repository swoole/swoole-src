--TEST--
swoole_http_client_coro: auto reconnect
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
        $cli->set(['timeout' => -1]);
        for ($n = MAX_REQUESTS; $n--;) {
            Assert::assert($cli->get('/'));
            Assert::same($cli->body, $pm->getRandomData(), var_dump_return($cli));
            co::sleep(0.005);
        }
    });
    swoole_event_wait();
    $pm->kill();
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
        $response->end($pm->getRandomData());
        co::sleep(0.001);
        $server->close($request->fd);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
