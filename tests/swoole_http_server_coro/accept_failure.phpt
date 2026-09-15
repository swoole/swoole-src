--TEST--
swoole_http_server_coro: report an accept failure
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
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

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0, true);
    Assert::true($server->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/client.key',
    ]));
    Assert::false($server->start());
    Assert::same($server->errCode, SWOOLE_ERROR_SSL_CREATE_CONTEXT_FAILED);
});

restore_error_handler();
Assert::count($warnings, 1);
Assert::startsWith($warnings[0], 'Swoole\\Coroutine\\Http\\Server::start(): accept failed, Error: ');
?>
--EXPECTF--
[%s]	WARNING	SSLContext::create(): SSL_CTX_use_PrivateKey_file(%s) failed, Error: %s[%d]
