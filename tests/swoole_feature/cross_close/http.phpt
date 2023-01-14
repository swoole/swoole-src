--TEST--
swoole_feature/cross_close: http client
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager();

$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $http = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        echo "GET\n";
        go(function () use ($pm, $http) {
            Co::sleep(0.001);
            echo "CLOSE\n";
            $http->close();
            $pm->kill();
            echo "DONE\n";
        });
        Assert::assert(!$http->get('/'));
        echo "CLOSED\n";
        Assert::same($http->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
        Assert::same($http->errCode, SOCKET_ECONNRESET);
        Assert::assert(empty($http->body));
    });
    Swoole\Event::wait();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('request', function ($request, Swoole\Http\Response $response) use ($server) {
        switch_process();
        co::sleep(3);
        $server->close($response->fd);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
GET
CLOSE
CLOSED
DONE
