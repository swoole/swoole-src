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
        $client->get('/');
        $ret = $client->upgrade('/');
        var_dump($ret);
        if ($ret) {
            $client->push('hello');
            var_dump(json_decode($client->recv()->data));
        }
        $client->close();

        var_dump($client->errMsg);
        echo "DONE\n";
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Websocket\Server('127.0.0.1', $pm->getFreePort());

    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $server->on('start', function ($server) {
    });

    $server->on('open', function($server, $req) {
        $server->push($req->fd, json_encode(['hello', 'world']));
    });

    $server->on('message', function($server, $frame) {
    });

    $server->on('close', function($server, $fd) {
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
bool(true)
array(2) {
  [0]=>
  string(5) "hello"
  [1]=>
  string(5) "world"
}
string(0) ""
DONE