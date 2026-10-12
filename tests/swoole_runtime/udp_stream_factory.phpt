--TEST--
swoole_runtime: UDP stream factories work inside and outside coroutines
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_UDP);

// The hooked factory must also delegate to PHP outside a coroutine.
$native = stream_socket_server('udp://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND);
if (!is_resource($native)) {
    throw new RuntimeException('Cannot create a native UDP stream');
}
fclose($native);

Swoole\Coroutine\run(function () {
    $stream = stream_socket_server('udp://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND);
    if (!is_resource($stream)) {
        throw new RuntimeException('Cannot create a coroutine UDP stream');
    }
    $address = stream_socket_get_name($stream, false);
    $port = (int) substr($address, strrpos($address, ':') + 1);
    $sender = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    Swoole\Coroutine::create(function () use ($sender, $port) {
        Swoole\Coroutine::sleep(0.01);
        if ($sender->sendto('127.0.0.1', $port, 'PING') !== 4) {
            throw new RuntimeException('Cannot send UDP packet');
        }
    });
    stream_set_timeout($stream, 2);
    if (stream_socket_recvfrom($stream, 16, 0, $peer) !== 'PING' || !str_starts_with($peer, '127.0.0.1:')) {
        throw new RuntimeException('Cannot receive UDP packet or source address');
    }
    fclose($stream);
    $sender->close();
});
Swoole\Runtime::enableCoroutine(0);
echo "DONE\n";
?>
--EXPECT--
DONE
