--TEST--
swoole_http_client_coro: defer concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$randomData = [];
for ($n = MAX_CONCURRENCY; $n--;) {
    $randomData[] = get_safe_random(rand(1024, 8192));
}

$pm->parentFunc = function () use ($pm, $randomData) {
    go(function () use ($pm, $randomData) {
        $clients = [];
        // normal
        for ($n = MAX_CONCURRENCY; $n--;) {
            $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 1]);
            $cli->setDefer();
            $clients[$n] = $cli;
            $retval = $cli->get('/?n=' . $n);
            Assert::assert($retval);
            if (!$retval)
            {
                var_dump($cli->errCode);
            }
        }
        for ($n = MAX_CONCURRENCY; $n--;) {
            $cli = $clients[$n];
            $cli->recv();
            Assert::same($cli->statusCode, 200);
            Assert::same($cli->body, $randomData[$n]);
        }
    });
    swoole_event_wait();
    $pm->kill();
    echo "OK\n";
};
$pm->childFunc = function () use ($pm, $randomData) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null'
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($pm, $server, $randomData) {
        $response->end($randomData[$request->get['n']]);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
