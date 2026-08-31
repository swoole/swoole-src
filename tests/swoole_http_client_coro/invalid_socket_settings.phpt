--TEST--
swoole_http_client_coro: reject invalid socket settings
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;

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
    $client = new Client('127.0.0.1', $port);
    Assert::true($client->set([
        'socks5_host' => '127.0.0.1',
        // Bound the unpatched path, which connects directly and waits for a response.
        'timeout' => 0.5,
    ]));

    // A retained socket would skip the settings on the second call and emit only one warning.
    $results = [$client->get('/'), $client->get('/')];
    Assert::same($results, [false, false]);
    Assert::same($client->errCode, SWOOLE_ERROR_INVALID_PARAMS);
    Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
    Assert::null($client->socket);
    Assert::count($warnings, 2);
    foreach ($warnings as $warning) {
        Assert::endsWith($warning, 'socks5_port should not be null');
    }

    $warnings = [];
    $client = new Client('127.0.0.1', $port);
    Assert::true($client->set(['defer' => true]));
    Assert::true($client->get('/'));
    $result = $client->set(['socks5_host' => '127.0.0.1']);
    // close() clears both properties, so capture the state after set() first.
    $connected = $client->connected;
    $socket = $client->socket;
    $client->close();

    Assert::false($result);
    Assert::true($connected);
    Assert::notNull($socket);
    Assert::count($warnings, 1);
    Assert::endsWith($warnings[0], 'socks5_port should not be null');
});

restore_error_handler();
fclose($server);
?>
--EXPECT--
