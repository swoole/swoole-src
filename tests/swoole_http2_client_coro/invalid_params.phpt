--TEST--
swoole_http2_client_coro: invalid parameters
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

try {
    new Swoole\Coroutine\Http2\Client('127.0.0.1', -1);
} catch (Swoole\Coroutine\Http2\Client\Exception $e) {
    echo $e->getMessage() . "\n";
}

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());
        Assert::false($client->write(-1, 'data'));
        $client->close();
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
        $response->end('ok');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
The port is invalid
