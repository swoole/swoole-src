--TEST--
swoole_http_server: numeric header name
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/'));
        Assert::eq($client->headers['12345'], 'hello');
        Assert::eq($client->headers['12345.678'], 'world');
        $pm->kill();
    });
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function ($request, Swoole\Http\Response $response) {
        $response->header(12345, 'hello');
        $response->header(12345.678, 'world');
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
