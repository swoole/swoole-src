--TEST--
swoole_http2_server: goaway
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 10]);
        Assert::true($cli->connect());
        Assert::greaterThan($streamId = $cli->send(new Swoole\Http2\Request), 0);
        $cli->recv();
        Assert::same($cli->serverLastStreamId, $streamId);
        Assert::same($cli->errCode, SWOOLE_HTTP2_ERROR_NO_ERROR);
        Assert::same($cli->errMsg, 'NO_ERROR');
        $pm->kill();
    });
    Swoole\Event::wait();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->goaway(SWOOLE_HTTP2_ERROR_NO_ERROR, 'NO_ERROR');
        $response->end($request->rawcontent());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
