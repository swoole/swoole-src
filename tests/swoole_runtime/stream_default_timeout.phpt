--TEST--
swoole_runtime: new client and accepted streams wait for data without an explicit timeout option
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
default_socket_timeout=1
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
Swoole\Coroutine\run(function () {
    $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    Assert::true($server !== false, $error);
    $address = stream_socket_get_name($server, false);
    go(function () use ($server) {
        $peer = stream_socket_accept($server, 1);
        Assert::true($peer !== false);
        Assert::same(fread($peer, 1), 'g');
        Assert::same(fwrite($peer, 'r'), 1);
        fclose($peer);
        fclose($server);
    });
    $client = stream_socket_client('tcp://' . $address, $errno, $error, 1);
    Assert::true($client !== false, $error);
    go(function () use ($client) {
        Swoole\Coroutine::sleep(0.03);
        Assert::same(fwrite($client, 'g'), 1);
    });
    Assert::same(fread($client, 1), 'r');
    Assert::false(stream_get_meta_data($client)['timed_out']);
    fclose($client);
});
echo "OK\n";
?>
--EXPECT--
OK
