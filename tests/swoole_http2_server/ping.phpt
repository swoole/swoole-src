--TEST--
swoole_http2_server: ping
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
        $s = microtime(true);
        $response = $cli->recv();
        time_approximate(0.5, microtime(true) - $s);
        Assert::same($response->streamId, $streamId);
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
        Swoole\Timer::tick(100, function (int $id) use ($request, $response) {
            Assert::true($response->ping());
            if (@++$GLOBALS['i'] === 5) {
                $response->end($request->rawcontent());
                Swoole\Timer::clear($id);
            }
        });
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
