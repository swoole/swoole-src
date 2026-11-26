--TEST--
swoole_http_client_coro: hand off unencoded SSE to the socket at the end of the response headers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;
use SwooleTest\Assert;

function acceptRequest(Socket $listener, Client $client): Socket
{
    Assert::true($client->get('/events'));
    $peer = $listener->accept(2);
    Assert::true($peer instanceof Socket);
    $request = '';
    while (!str_contains($request, "\r\n\r\n")) {
        $chunk = $peer->recv(4096, 2);
        Assert::notEmpty($chunk);
        $request .= $chunk;
    }
    return $peer;
}

Assert::setThrowException(true);
Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0) && $listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $client->set(['timeout' => 2]);
    $client->setDefer(true);
    $headers = "HTTP/1.1 200 OK\r\nContent-Type: Text/Event-Stream; charset=UTF-8\r\n";

    $peer = acceptRequest($listener, $client);
    $first = $headers . "Connection: close\r\n\r\ndata: first\n\n";
    Assert::same($peer->sendAll($first), strlen($first));
    Assert::true($client->recv());
    Assert::same($client->statusCode, 200);
    Assert::same($client->getBody(), '');
    $socket = $client->socket;
    Assert::true($socket instanceof Socket);
    Assert::same($socket->recvLine(), "data: first\n");
    Assert::same($socket->recvLine(), "\n");

    Assert::false($client->get('/while-reading-events'));
    Assert::same($client->errCode, SOCKET_EBUSY);
    $second = "data: second\n\n";
    Assert::same($peer->sendAll($second), strlen($second));
    Assert::same($socket->recvLine(), "data: second\n");
    Assert::same($socket->recvLine(), "\n");
    Assert::true($socket->close());
    Assert::false($client->connected);
    $peer->close();

    $body = "data: framed\n\n";
    foreach ([
        "Content-Length: " . strlen($body) . "\r\n\r\n" . $body,
        "Transfer-Encoding: chunked\r\n\r\n" . dechex(strlen($body)) . "\r\n" . $body . "\r\n0\r\n\r\n",
    ] as $framed) {
        $peer = acceptRequest($listener, $client);
        $response = $headers . $framed;
        Assert::same($peer->sendAll($response), strlen($response));
        Assert::true($client->recv());
        Assert::same($client->getBody(), $body);
        $client->close();
        $peer->close();
    }
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
