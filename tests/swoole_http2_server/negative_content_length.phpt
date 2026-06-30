--TEST--
swoole_http2_server: negative content-length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($cli->connect());

        $request = new Swoole\Http2\Request();
        $request->method = 'POST';
        $request->path = '/';
        $request->headers = [
            'content-length' => '-1',
        ];

        Assert::greaterThan($cli->send($request), 0);
        $response = $cli->recv();
        Assert::same($response->statusCode, 413);
        $cli->close();
    });
    Swoole\Event::wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('unexpected');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
