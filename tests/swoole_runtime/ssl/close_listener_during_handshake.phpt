--TEST--
swoole_runtime: a closed TLS listener cannot publish an accepted stream after its handshake
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_no_ssl();
skip_if_extension_not_exist('openssl');
?>
--FILE--
<?php
require __DIR__ . '/../../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Runtime;
use SwooleTest\Assert;

Runtime::enableCoroutine(SWOOLE_HOOK_TCP | SWOOLE_HOOK_SSL);
Coroutine\run(function () {
    $certs = __DIR__ . '/../../include/ssl_certs/';
    $context = stream_context_create(['ssl' => [
        'local_cert' => $certs . 'server.crt',
        'local_pk' => $certs . 'server.key',
        'verify_peer' => false,
        'verify_peer_name' => false,
    ]]);
    $listener = stream_socket_server('ssl://127.0.0.1:0', $errno, $error,
        STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
    Assert::resource($listener);
    stream_set_timeout($listener, 2);
    $client = stream_socket_client('tcp://' . stream_socket_get_name($listener, false));
    Assert::resource($client);
    stream_context_set_option($client, 'ssl', 'verify_peer', false);
    stream_context_set_option($client, 'ssl', 'verify_peer_name', false);
    $done = new Channel(1);
    Coroutine::create(function () use ($listener, $done) {
        Assert::false(@stream_socket_accept($listener, 2));
        $done->push(true);
    });
    // Give asynchronous accept a dispatch pass to enter TLS. Both sides of that race must be safe;
    // the assertion does not depend on whether the kernel has delivered its accept completion yet.
    Coroutine::sleep(0.01);
    Assert::same($done->length(), 0);
    Assert::true(fclose($listener));
    @stream_socket_enable_crypto($client, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    Assert::true($done->pop(3));
    fclose($client);
});
echo "DONE\n";
?>
--EXPECT--
DONE
