--TEST--
swoole_http2_client_coro: reject oversized GOAWAY debug data before writing
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;

Swoole\Coroutine\run(static function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    Assert::true($client->connect());
    $peer = $listener->accept(1);
    Assert::isInstanceOf($peer, Socket::class);
    Assert::false(@$client->goaway(0, str_repeat('X', 16384 - 7)));
    Assert::false(@$client->goaway(0, str_repeat('X', 1 << 24)));
    Assert::true($client->connected);
    $debug = str_repeat('X', 16384 - 8);
    Assert::true($client->goaway(SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM, $debug));
    Assert::same($peer->recvAll(24, 1), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    do {
        $header = $peer->recvAll(9, 1);
        Assert::same(strlen($header), 9);
        $length = unpack('N', "\0" . substr($header, 0, 3))[1];
        $payload = $length ? $peer->recvAll($length, 1) : '';
    } while (ord($header[3]) !== SWOOLE_HTTP2_TYPE_GOAWAY);
    Assert::same($length, 16384);
    Assert::same(ord($header[4]), 0);
    Assert::same(unpack('N', substr($header, 5))[1], 0);
    Assert::same($payload, pack('NN', 0, SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM) . $debug);
    $client->close();
    $peer->close();
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
