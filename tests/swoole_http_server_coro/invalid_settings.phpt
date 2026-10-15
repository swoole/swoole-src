--TEST--
swoole_http_server_coro: reject invalid startup settings
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;

$warnings = [];
set_error_handler(function ($errno, $message) use (&$warnings) {
    $warnings[] = $message;
    return true;
});

Coroutine\run(function () use (&$warnings) {
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use ($server) {
        $response->end('OK');
        $server->shutdown();
    });
    Assert::true($server->set(['package_length_type' => '?']));

    $cid = Coroutine::create(function () use ($server) {
        Coroutine::sleep(0.01);
        $server->shutdown();
    });

    try {
        $server->start();
        Assert::true(false, 'invalid settings must throw before accepting connections');
    } catch (Swoole\Exception $exception) {
        Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        Assert::contains($exception->getMessage(), 'package_length_type');
    }
    Assert::true(Coroutine::join([$cid]));
    Assert::same($server->errCode, SOCKET_EINVAL);
    Assert::same($server->errMsg, swoole_strerror(SOCKET_EINVAL));
    Assert::same($warnings, []);

    $warnings = [];
    Assert::true($server->set(['package_length_type' => 'N']));
    $cid = Coroutine::create(function () use ($server) {
        Coroutine::sleep(0.01);
        Assert::same(httpGetBody("http://127.0.0.1:{$server->port}/"), 'OK');
    });
    Assert::true($server->start());
    Assert::true(Coroutine::join([$cid]));
    Assert::same($warnings, []);
});

restore_error_handler();
?>
--EXPECT--
