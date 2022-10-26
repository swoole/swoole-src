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
        var_dump($client->get('/close'));
        var_dump($client->getHeaders());

        var_dump($client->get('/keep_alive'));
        var_dump($client->getHeaders());
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

    $server->on('request', function($request, $response) {
        if ($request->server['request_uri'] == '/close') {
            $response->header('connection', 'close');
        }
        $response->end();
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
bool(true)
array(5) {
  ["connection"]=>
  string(5) "close"
  ["server"]=>
  string(18) "swoole-http-server"
  ["content-type"]=>
  string(9) "text/html"
  ["date"]=>
  string(%d) "%s"
  ["content-length"]=>
  string(1) "0"
}
bool(true)
array(5) {
  ["server"]=>
  string(18) "swoole-http-server"
  ["connection"]=>
  string(10) "keep-alive"
  ["content-type"]=>
  string(9) "text/html"
  ["date"]=>
  string(%d) "%s"
  ["content-length"]=>
  string(1) "0"
}
string(0) ""
DONE
