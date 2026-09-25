--TEST--
swoole_client_coro: reject invalid TLS settings in enableSSL
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

Co::set(['log_file' => '/dev/null']);

$serverResult = null;
$warnings = [];

run(function () use (&$serverResult, &$warnings) {
    $server = new Server('127.0.0.1', 0, true);
    $server->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $server->handle(function (Connection $conn) {
        $data = $conn->recv();
        $conn->send($data);
    });
    go(function () use ($server, &$serverResult) {
        $serverResult = $server->start();
    });

    set_error_handler(function ($errno, $message) use (&$warnings) {
        $warnings[] = $message;
        return true;
    });

    $missingCert = __DIR__ . '/missing.crt';
    $client = new Client(SWOOLE_SOCK_TCP);
    Assert::true($client->connect('127.0.0.1', $server->port));
    Assert::true($client->set([
        'ssl_cert_file' => $missingCert,
        // This setting used to be skipped after the invalid certificate while the handshake still succeeded.
        'ssl_verify_peer' => true,
    ]));
    Assert::false($client->enableSSL());
    Assert::eq($client->errCode, SWOOLE_ERROR_INVALID_PARAMS);
    Assert::null($client->socket);
    Assert::false($client->connected);
    Assert::count($warnings, 1);
    Assert::endsWith($warnings[0], "ssl cert file[{$missingCert}] not found");

    Assert::false($client->enableSSL());
    Assert::eq($client->errCode, SWOOLE_ERROR_CLIENT_NO_CONNECTION);

    // Close the connection left open by the unfixed implementation.
    $client->close();

    restore_error_handler();

    $client = new Client(SWOOLE_SOCK_TCP);
    Assert::true($client->connect('127.0.0.1', $server->port));
    Assert::true($client->set([
        // Keep the settings array non-empty so enableSSL() applies it.
        'ssl_verify_peer' => false,
    ]));
    Assert::true($client->enableSSL());
    Assert::same($client->send('valid'), 5);
    Assert::same($client->recv(), 'valid');
    Assert::true($client->close());

    $server->shutdown();
});

Assert::true($serverResult);
?>
--EXPECT--
