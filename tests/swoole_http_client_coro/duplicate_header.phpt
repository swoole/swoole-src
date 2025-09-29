--TEST--
swoole_http_server: duplicate header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$uuid = uniqid();
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $uuid) {
    Co\run(function () use ($pm, $uuid) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/'));
        Assert::eq($client->headers['values-1'], ['hello', 'swoole', $uuid]);
        Assert::eq($client->headers['values-2'], ['hello', $uuid]);
        $pm->kill();
    });
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $uuid) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function ($request, Swoole\Http\Response $response) use ($uuid) {
        $response->header('values-1', ['hello', 'swoole', $uuid]);
        $response->header('values-2', ['hello', $uuid]);
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
