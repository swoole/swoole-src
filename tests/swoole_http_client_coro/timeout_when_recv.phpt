--TEST--
swoole_http_client_coro: timeout in recv
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$port = get_one_free_port();
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $port) {
    go(function () use ($pm, $port) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
        $cli->set(['timeout' => 0.1]);
        $cli->setHeaders([
            'hello' => 'swoole'
        ]);
        $cli->setDefer();
        $cli->get('/');
        Assert::assert(!$cli->recv());
        Assert::assert(empty($cli->body));
        $pm->kill();
    });
    swoole_event_wait();
};

$pm->childFunc = function () use ($pm, $port) {
    $serv = new swoole_http_server('127.0.0.1', $port, SWOOLE_BASE);
    $serv->set([
        'log_file' => '/dev/null'
    ]);
    $serv->on('WorkerStart', function (swoole_http_server $serv) {
        global $pm;
        $pm->wakeup();
    });
    $serv->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        Assert::same($request->header['hello'], 'swoole');
        co::sleep(2);
        $response->end('ok!');
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
