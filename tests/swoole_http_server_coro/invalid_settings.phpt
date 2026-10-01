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

    // The warning is emitted on the unchanged branch too; the return value proves the setting was rejected.
    Assert::false($server->start());
    Assert::true(Coroutine::join([$cid]));
    Assert::same($server->errCode, SOCKET_EINVAL);
    Assert::same($server->errMsg, swoole_strerror(SOCKET_EINVAL));
    Assert::same($warnings, [
        "Swoole\\Coroutine\\Http\\Server::start(): Unknown package_length_type name '?', see pack(). Link: https://php.net/pack",
    ]);

    $warnings = [];
    Assert::true($server->set(['package_length_type' => 'N']));
    $cid = Coroutine::create(function () use ($server) {
        Coroutine::sleep(0.01);
        Assert::same(httpGetBody("http://127.0.0.1:{$server->port}/"), 'OK');
    });
    Assert::true($server->start());
    Assert::true(Coroutine::join([$cid]));
    Assert::same($warnings, []);

    $server = new Server('127.0.0.1', 0, true);
    $server->handle('/', function ($request, $response) use ($server) {
        $response->end('OK');
        $server->shutdown();
    });
    Assert::true($server->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        'ssl_client_cert_file' => __DIR__ . '/not-found.pem',
    ]));

    $cid = Coroutine::create(function () use ($server) {
        Coroutine::sleep(0.01);
        $server->shutdown();
    });

    Assert::false($server->start());
    Assert::true(Coroutine::join([$cid]));
    Assert::same($server->errCode, SOCKET_EINVAL);
    Assert::same($server->errMsg, swoole_strerror(SOCKET_EINVAL));
    Assert::same($warnings, [
        'Swoole\\Coroutine\\Http\\Server::start(): ssl client cert file[' . __DIR__ . '/not-found.pem] not found',
    ]);

    $warnings = [];
    Assert::true($server->set(['ssl_client_cert_file' => SSL_FILE_DIR . '/ca-cert.pem']));
    $cid = Coroutine::create(function () use ($server) {
        Coroutine::sleep(0.01);
        Assert::same(httpGetBody("https://127.0.0.1:{$server->port}/"), 'OK');
    });
    Assert::true($server->start());
    Assert::true(Coroutine::join([$cid]));
    Assert::same($warnings, []);
});

restore_error_handler();
?>
--EXPECTF--
[%s]	WARNING	SSLContext::set_client_cert_file(): ssl client cert file[%s] not found
