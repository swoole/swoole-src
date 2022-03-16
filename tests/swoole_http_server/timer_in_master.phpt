--TEST--
swoole_http_server: timer in master
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->get('/');
        $cli->close();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->on('start', function (Swoole\Server $server) {
        $server->tick(1000, function($timerId) {
            $a = $timerId;
        });
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($server){
        $server->shutdown();
    });
    $server->on('shutdown', function () {
        echo "Shutdown Called";
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	INFO	Server is shutdown now
Shutdown Called
