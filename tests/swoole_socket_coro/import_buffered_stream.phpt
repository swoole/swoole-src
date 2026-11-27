--TEST--
swoole_socket_coro: reject importing unread stream buffers without changing the stream
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;
use SwooleTest\Assert;

Assert::setThrowException(true);
$listener = stream_socket_server('tcp://127.0.0.1:0');
$client = stream_socket_client('tcp://' . stream_socket_get_name($listener, false));
$peer = stream_socket_accept($listener, 2);
fwrite($client, 'ABC');
Assert::same(fread($peer, 1), 'A');
Assert::same(stream_get_meta_data($peer)['unread_bytes'], 2);
Coroutine\run(function () use ($peer, $client) {
    $warnings = [];
    set_error_handler(function ($severity, $message) use (&$warnings) {
        $warnings[] = $message;
        return true;
    });
    try {
        Assert::false(Socket::import($peer));
    } finally {
        restore_error_handler();
    }
    Assert::count($warnings, 1);
    Assert::contains($warnings[0], 'cannot import a stream with unread buffered data');
    Assert::same(swoole_last_error(), SOCKET_EBUSY);
    Assert::same(stream_get_meta_data($peer)['unread_bytes'], 2);
    Assert::same(fread($peer, 2), 'BC');
    $socket = Socket::import($peer);
    Assert::isInstanceOf($socket, Socket::class);
    Assert::same(fwrite($client, 'DE'), 2);
    Assert::same($socket->recv(2, 2), 'DE');
    $socket->close();
});
fclose($client);
fclose($listener);
echo "DONE\n";
?>
--EXPECT--
DONE
