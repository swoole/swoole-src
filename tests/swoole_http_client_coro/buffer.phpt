--TEST--
swoole_http_client_coro: use buffer body
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('travis network');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$count = 0;
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, &$count) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm, &$count) {
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            for ($n = MAX_REQUESTS; $n--;) {
                $cli->set(['timeout' => 5]);
                $cli->setMethod('POST');
                $buffer = new swoole_buffer(128);
                $buffer->append('Swoole');
                $cli->setData($buffer);
                $cli->execute('/');
                if ($cli->body === 'Hello Swoole!') {
                    $count++;
                }
            }
        });
    }
    swoole_event_wait();
    Assert::same($count, (MAX_CONCURRENCY_MID * MAX_REQUESTS));
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set(['log_file' => '/dev/null']);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->end("Hello {$request->rawcontent()}!");
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
