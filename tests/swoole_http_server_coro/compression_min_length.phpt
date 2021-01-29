--TEST--
swoole_http_server_coro: compression_min_length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Runtime;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

define('TEST_PORT', get_one_free_port());

Runtime::setHookFlags(SWOOLE_HOOK_ALL);

run(function () {
    go(function () {
        $server = new Server("127.0.0.1", TEST_PORT, false);
        $server->set(['compression_min_length' => 128,]);
        $server->handle('/test', function ($request, $response) {
            $response->end(str_repeat('A', $request->get['bytes']));
        });
        $server->handle('/shutdown', function ($request, $response) use ($server) {
            $response->end("shutdown");
            $server->shutdown();
        });
        $server->start();
    });
    
    go(function () {
        $cli = new Client('127.0.0.1', TEST_PORT);
        $cli->setHeaders(['Accept-Encoding' => 'gzip', ]);
        $cli->get('/test?bytes=128');
        Assert::eq($cli->getHeaders()['content-encoding'], 'gzip');

        $cli = new Client('127.0.0.1', TEST_PORT);
        $cli->setHeaders(['Accept-Encoding' => 'gzip', ]);
        $cli->get('/test?bytes=127');
        Assert::assert(!isset($cli->getHeaders()['content-encoding']));

        file_get_contents('http://127.0.0.1:' . TEST_PORT . '/shutdown');
    });
});
echo "DONE\n";
?>
--EXPECT--
DONE
