--TEST--
swoole_http_server: disable compression
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
        Assert::eq(md5_file(__DIR__ . '/../../README.md'), md5($client->getBody()));
        Assert::keyNotExists($client->headers, 'content-encoding');
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
        // Set Content-Encoding header to empty to disable compression
        $response->header('Content-Encoding', '');
        $response->end(co::readFile(__DIR__ . '/../../README.md'));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
