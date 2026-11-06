--TEST--
swoole_runtime/ssl: zero timeout keeps native OpenSSL stream reads blocking
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
Swoole\Coroutine\run(function () {
    $context = stream_context_create(['ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
        'local_cert' => SSL_FILE_DIR . '/server.crt',
        'local_pk' => SSL_FILE_DIR . '/server.key',
    ]]);
    $server = stream_socket_server('ssl://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
    Assert::true($server !== false, $error);
    $address = stream_socket_get_name($server, false);
    $release = new Swoole\Coroutine\Channel(1);
    go(function () use ($server, $release) {
        $peer = stream_socket_accept($server, 2);
        Assert::true($peer !== false);
        Swoole\Coroutine::sleep(0.1);
        Assert::same(fwrite($peer, 'r'), 1);
        Assert::true($release->pop(2));
        fclose($peer);
        fclose($server);
    });

    $clientContext = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
    $stream = stream_socket_client('ssl://' . $address, $errno, $error, 2, STREAM_CLIENT_CONNECT, $clientContext);
    Assert::true($stream !== false, $error);
    stream_set_timeout($stream, 0, 10000);
    stream_set_timeout($stream, 0, 0);
    Assert::same(fread($stream, 1), 'r');
    Assert::false(stream_get_meta_data($stream)['timed_out']);
    Assert::false(stream_get_meta_data($stream)['eof']);
    fclose($stream);
    $release->push(true);
});
echo "OK\n";
?>
--EXPECT--
OK
