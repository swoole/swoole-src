--TEST--
swoole_http2_client_coro: close the connection when a write fails
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;

Coroutine\run(function () {
    // The peer never reads, so a large request body waits for the socket. $peer keeps each connection open.
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1') && $listener->listen());
    $accepted = new Channel(1);
    Coroutine::create(function () use ($listener, $accepted) {
        while (($peer = $listener->accept(-1)) !== false) {
            $accepted->push($peer);
        }
    });
    $request         = new Request();
    $request->method = 'POST';
    $request->data   = ['data' => str_repeat('a', 8 * 1024 * 1024)];

    // A failed write closes the connection and keeps its error.
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $client->set(['write_timeout' => 0.5]);
    Assert::true($client->connect());
    $peer = $accepted->pop(1);
    Assert::false($client->send($request));
    Assert::same($client->errCode, SOCKET_ETIMEDOUT);
    Assert::false($client->connected);
    Assert::false($client->send(new Request()));
    Assert::same($client->errCode, SWOOLE_ERROR_CLIENT_NO_CONNECTION);

    // A coroutine waiting in recv() is woken up and finishes the close.
    Assert::true($client->connect());
    $peer   = $accepted->pop(1);
    $reader = new Channel(1);
    Coroutine::create(function () use ($client, $reader) {
        $reader->push($client->recv(-1) === false);
    });
    Assert::false($client->send($request));
    Assert::same($client->errCode, SOCKET_ETIMEDOUT);
    Assert::true($reader->pop(1));
    Assert::null($client->socket);

    // A GOAWAY while a write waits closes the connection and keeps the server's error.
    Assert::true($client->connect());
    $peer = $accepted->pop(1);
    $client->set(['write_timeout' => 5]);
    $writer = new Channel(1);
    Coroutine::create(function () use ($client, $request, $writer) {
        $writer->push($client->send($request) === false);
    });
    $goaway = pack('NN', 0, SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM) . 'slow down';
    $peer->sendAll(substr(pack('N', strlen($goaway)), 1) . "\x07\x00" . pack('N', 0) . $goaway);
    Assert::false($client->recv(5));
    Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_ENHANCE_YOUR_CALM);
    Assert::same($client->errMsg, 'slow down');
    Assert::true($writer->pop(1));
    Assert::false($client->connected);

    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
