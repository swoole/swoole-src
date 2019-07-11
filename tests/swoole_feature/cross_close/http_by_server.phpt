--TEST--
swoole_feature/cross_close: http client closed by server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $http = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        echo "GET\n";
        Assert::assert(!$http->get('/'));
        echo "CLOSED\n";
        Assert::same($http->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
        Assert::same($http->errCode, SOCKET_ECONNRESET);
        Assert::assert(empty($http->body));
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('request', function ($request, Swoole\Http\Response $response) use ($server) {
        switch_process();
        echo "CLOSE\n";
        $server->close($response->fd);
        switch_process();
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
