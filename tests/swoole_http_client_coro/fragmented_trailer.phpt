--TEST--
swoole_http_client_coro: preserve fragmented trailer fields
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;

Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $cid = Coroutine::create(function () use ($listener) {
        $peer = $listener->accept(2);
        Assert::isInstanceOf($peer, Socket::class);
        $request = '';
        while (!str_contains($request, "\r\n\r\n")) {
            $data = $peer->recv(8192, 2);
            Assert::notEmpty($data);
            $request .= $data;
        }
        $response = "HTTP/1.1 200 OK\r\n"
            . "Transfer-Encoding: chunked\r\n"
            . "Connection: close\r\n\r\n"
            . "1\r\na\r\n0\r\n";
        Assert::same($peer->sendAll($response, 2), strlen($response));
        foreach (str_split("X-Trailer: yes\r\nX-Empty:\r\n\r\n") as $byte) {
            Assert::same($peer->sendAll($byte, 2), 1);
            Coroutine::sleep(0.001);
        }
        $peer->close();
    });

    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $client->set(['timeout' => 2]);
    Assert::true($client->get('/'));
    Assert::same($client->body, 'a');
    Assert::same($client->headers['x-trailer'] ?? null, 'yes');
    Assert::same($client->headers['x-empty'] ?? null, '');

    $client->close();
    Coroutine::join([$cid]);
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
