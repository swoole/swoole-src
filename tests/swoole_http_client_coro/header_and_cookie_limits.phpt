--TEST--
swoole_http_client_coro: header and cookie limits
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $headerClient = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $headerClient->set(['timeout' => 3]);
        Assert::true($headerClient->get('/'));
        $headerClient->setHeaders([
            'Connection' => str_repeat('keep-alive, ', 8 * 1024),
        ]);
        try {
            $headerClient->get('/');
            Assert::true(false);
        } catch (Swoole\Coroutine\Http\Client\Exception $e) {
            Assert::contains($e->getMessage(), 'header block is too large');
        }

        $cookieClient = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cookieClient->set(['timeout' => 3]);
        $cookieClient->setHeaders(['Connection' => 'close']);
        $cookieClient->setCookies([
            'token' => str_repeat('b', 4097),
        ]);
        try {
            $cookieClient->get('/');
            Assert::true(false);
        } catch (Swoole\Coroutine\Http\Client\Exception $e) {
            Assert::contains($e->getMessage(), 'cookie header is too large');
        }
        $cookieClient->setHeaders([]);
        $cookieClient->setCookies([]);
        Assert::true($cookieClient->get('/'));
        Assert::true($cookieClient->connected);
        $cookieClient->close();
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('OK');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
