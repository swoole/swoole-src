--TEST--
swoole_http_server_coro: error 413
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

define('TEST_PORT', get_one_free_port());

go(function () {
    $server = new Co\Http\Server("127.0.0.1", TEST_PORT, false);
    $server->set(['package_max_length' => 65536, ]);
    $server->handle('/', function ($request, $response) {
        $response->end(serialize($request->server));
    });
    $server->handle('/shutdown', function ($request, $response) use ($server) {
        $response->end("shutdown");
        $server->shutdown();
    });
    $server->start();
});

go(function () {
    $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', TEST_PORT, false);
    $cli->set(['timeout' => 5]);
    Assert::assert($cli->post('/world/index?b=455', ['value' => str_repeat('A', 128 * 1024 )]));
    Assert::assert($cli->getStatusCode() == 413);
    file_get_contents('http://127.0.0.1:' . TEST_PORT . '/shutdown');
});

swoole_event_wait();
?>
--EXPECT--
