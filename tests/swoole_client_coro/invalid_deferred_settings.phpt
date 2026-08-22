--TEST--
swoole_client_coro: reject invalid deferred settings
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;

use function Swoole\Coroutine\run;

$server = stream_socket_server('tcp://127.0.0.1:0');
$address = stream_socket_get_name($server, false);
$port = (int) substr($address, strrpos($address, ':') + 1);
$warnings = [];

set_error_handler(function ($errno, $message) use (&$warnings) {
    $warnings[] = $message;
    return true;
});

run(function () use ($port, &$warnings) {
    $client = new Client(SWOOLE_SOCK_TCP);
    Assert::true($client->set([
        'socks5_host' => '127.0.0.1',
    ]));

    // Retry with the same client to verify that the rejected socket was released.
    $results = [
        $client->connect('127.0.0.1', $port),
        $client->connect('127.0.0.1', $port),
    ];
    Assert::same($results, [false, false]);
    Assert::eq($client->errCode, SWOOLE_ERROR_INVALID_PARAMS);
    Assert::null($client->socket);
    Assert::count($warnings, 2);
    foreach ($warnings as $warning) {
        Assert::endsWith($warning, 'socks5_port should not be null');
    }

    $warnings = [];
    $client = new Client(SWOOLE_SOCK_TCP);
    Assert::true($client->set([
        'http_proxy_host' => '127.0.0.1',
        'http_proxy_port' => null,
    ]));
    Assert::false($client->connect('127.0.0.1', $port));
    Assert::eq($client->errCode, SWOOLE_ERROR_INVALID_PARAMS);
    Assert::null($client->socket);
    Assert::count($warnings, 1);
    Assert::endsWith($warnings[0], 'http_proxy_port should not be null');

    $warnings = [];
    $client = new Client(SWOOLE_SOCK_TCP);
    Assert::true($client->set([
        'package_length_type' => '?',
    ]));
    Assert::false($client->connect('127.0.0.1', $port));
    Assert::eq($client->errCode, SWOOLE_ERROR_INVALID_PARAMS);
    Assert::null($client->socket);
    Assert::count($warnings, 1);
    Assert::endsWith($warnings[0], "Unknown package_length_type name '?', see pack(). Link: https://php.net/pack");
});

restore_error_handler();
fclose($server);
?>
--EXPECT--
