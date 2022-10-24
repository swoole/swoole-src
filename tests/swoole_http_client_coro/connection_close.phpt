--TEST--
swoole_http_client_coro: connection close
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $ret = $client->get('/');
        var_dump($ret);

        $ret = $client->get('/');
        var_dump($ret);
        $client->close();

        var_dump($client->errMsg);
        echo "DONE\n";
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('request', function($server, $req) {
        $req->header('connection', 'close');
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
bool(true)
bool(true)
string(0) ""
DONE
