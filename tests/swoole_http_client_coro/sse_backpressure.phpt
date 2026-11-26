--TEST--
swoole_http_client_coro: SSE events survive fragmented sends and TCP backpressure
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;
use Swoole\Event;
use Swoole\Runtime;
use SwooleTest\Assert;

Assert::setThrowException(true);
Runtime::enableCoroutine(SWOOLE_HOOK_SLEEP);
Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $readerPaused = new Channel(1);
    $writePending = new Channel(1);
    $payload = str_repeat('x', 512 * 1024);

    Coroutine::create(function () use ($listener, $readerPaused, $writePending, $payload) {
        $peer = $listener->accept(5);
        Assert::true($peer instanceof Socket);
        try {
            Assert::true($peer->setOption(SOL_SOCKET, SO_SNDBUF, 32 * 1024));
            $request = '';
            while (!str_contains($request, "\r\n\r\n")) {
                $chunk = $peer->recv(4096, 5);
                Assert::notEmpty($chunk);
                $request .= $chunk;
            }
            $head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: ";
            Assert::same($peer->sendAll($head, 5), strlen($head));
            Assert::true($readerPaused->pop(5));

            usleep(mt_rand(1000, 8000));
            $writer = Coroutine::getCid();
            // The write must yield while the reader is paused and the TCP buffers fill up.
            Event::defer(function () use ($peer, $writePending, $writer) {
                $writePending->push($peer->getBoundCid(SWOOLE_EVENT_WRITE) === $writer);
            });
            Assert::same($peer->sendAll($payload, 5), strlen($payload));

            foreach (["\n", "\ndata: sec", "ond\n", "\ndata: third\n\n"] as $part) {
                usleep(mt_rand(1000, 8000));
                Assert::same($peer->sendAll($part, 5), strlen($part));
            }
        } finally {
            $peer->close();
        }
    });

    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $body = '';
    $client->set([
        'timeout' => 10,
        'socket_buffer_size' => 64 * 1024,
        'write_func' => function (Client $client, string $chunk) use ($readerPaused, $writePending, &$body) {
            if ($body === '') {
                Assert::true($readerPaused->push(true));
                Assert::true($writePending->pop(5), 'Expected a pending server write while the reader was paused');
            }
            $body .= $chunk;
        },
    ]);

    Assert::true($client->get('/events'));
    Assert::same($client->statusCode, 200);
    $expected = "data: {$payload}\n\ndata: second\n\ndata: third\n\n";
    Assert::same($body, $expected, 'SSE events must arrive in order with their complete payloads');
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
