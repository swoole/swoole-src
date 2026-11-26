--TEST--
swoole_http_client_coro: close-delimited SSE completes at EOF
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $received = new Channel(1);
    $closed = false;

    Coroutine::create(function () use ($listener, $received, &$closed) {
        $peer = $listener->accept(2);
        Assert::true($peer instanceof Socket);
        try {
            $request = '';
            while (!str_contains($request, "\r\n\r\n")) {
                $chunk = $peer->recv(4096, 2);
                Assert::notEmpty($chunk);
                $request .= $chunk;
            }
            $headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
            foreach ([$headers . "data: one\n\n", "data: two\n\n"] as $part) {
                Assert::same($peer->sendAll($part), strlen($part));
                if (!$received->pop(2)) {
                    return;
                }
            }
        } finally {
            $closed = $peer->close();
        }
    });

    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $events = [];
    $buffer = '';
    $client->set(['timeout' => 3, 'write_func' => function (Client $client, string $chunk) use ($received, &$events, &$buffer) {
        $buffer .= $chunk;
        while (($end = strpos($buffer, "\n\n")) !== false) {
            $events[] = substr($buffer, 0, $end);
            $buffer = substr($buffer, $end + 2);
            $received->push(true);
        }
    }]);
    try {
        Assert::true($client->get('/events'));
        Assert::same($events, ['data: one', 'data: two'], 'Both SSE events must be delivered before completion');
        Assert::true($closed);
        Assert::same($client->statusCode, 200);
    } finally {
        $received->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
