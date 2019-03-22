--TEST--
swoole_feature: cross_close: http client
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
        go(function () use ($pm, $http) {
            Co::sleep(0.001);
            echo "CLOSE\n";
            $http->close();
            $pm->kill();
            echo "DONE\n";
        });
        assert(!$http->get('/'));
        echo "CLOSED\n";
        assert($http->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
        assert($http->errCode === SOCKET_ECONNRESET);
        assert(empty($http->body));
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('request', function ($request, Swoole\Http\Response $response) use ($server) {
        switch_process();
        co::sleep(5);
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
