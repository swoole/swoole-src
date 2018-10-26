--TEST--
swoole_http_client_coro: illegal another coroutine
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    $process = new swoole_process(function (swoole_process $worker) use ($pm) {
        function close(Swoole\Coroutine\Http\Client $client)
        {
            $client->close();
        }

        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        go(function () use ($cli) {
            (function () use ($cli) {
                (function () use ($cli) {
                    co::sleep(0.001);
                    close($cli);
                })();
            })();
        });
        go(function () use ($cli) {
            $cli->get('/');
        });
        swoole_event_wait();
    }, false);
    $process->start();
    swoole_process::wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new swoole_http_server('127.0.0.1', $pm->getFreePort(), mt_rand(0, 1) ? SWOOLE_BASE : SWOOLE_PROCESS);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function (swoole_http_server $server) use ($pm) {
        $pm->wakeup();
        co::sleep(0.5);
        $server->shutdown();
    });
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($pm, $server) {
        co::sleep(0.1);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	ERROR	http client has already been bound to another coroutine #%d, reading or writing of the same socket in multiple coroutines at the same time is not allowed.
Stack trace:
#0  Swoole\Coroutine\Http\Client->close() called at [%s:%d]
#1  close() called at [%s:%d]
#2  {closure}() called at [%s:%d]