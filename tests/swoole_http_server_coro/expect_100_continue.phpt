--TEST--
swoole_http_server_coro: send 100 Continue before receiving the request body
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Socket;
use Swoole\Http\Request;
use Swoole\Http\Response;

function recv_all(Socket $socket): string
{
    $response = '';
    while (($data = $socket->recv()) !== '' && $data !== false) {
        $response .= $data;
    }
    return $response;
}

function connect_to(Server $server): Socket
{
    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $server->port, -1));
    return $socket;
}

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $continue = "HTTP/1.1 100 Continue\r\n\r\n";
    Coroutine::create(function () use ($server) {
        $server->handle('/', function (Request $request, Response $response) {
            $response->end($request->rawContent());
        });
        $server->start();
    });
    Coroutine::sleep(0.001);

    $body = 'content-length-body';
    $headers = "POST / HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Expect: 100-continue\r\n" .
        'Content-Length: ' . strlen($body) . "\r\n" .
        "Connection: close\r\n\r\n";
    $socket = connect_to($server);
    Assert::same($socket->sendAll($headers), strlen($headers));
    Assert::same($socket->recvAll(strlen($continue), 1), $continue);
    Assert::same($socket->sendAll(substr($body, 0, 8)), 8);
    Coroutine::sleep(0.05);
    Assert::same($socket->sendAll(substr($body, 8)), strlen($body) - 8);
    $response = recv_all($socket);
    Assert::notContains($response, $continue);
    Assert::contains($response, $body);

    $body = 'chunked-body';
    $headers = "POST / HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Expect: 100-continue\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n";
    $chunks = dechex(strlen($body)) . "\r\n{$body}\r\n0\r\n\r\n";
    $socket = connect_to($server);
    Assert::same($socket->sendAll($headers), strlen($headers));
    Assert::same($socket->recvAll(strlen($continue), 1), $continue);
    Assert::same($socket->sendAll($chunks), strlen($chunks));
    Assert::contains(recv_all($socket), $body);

    $body = 'ordinary-body';
    $request = "POST / HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        'Content-Length: ' . strlen($body) . "\r\n" .
        "Connection: close\r\n\r\n{$body}";
    $socket = connect_to($server);
    Assert::same($socket->sendAll($request), strlen($request));
    $response = recv_all($socket);
    Assert::notContains($response, 'HTTP/1.1 100 Continue');
    Assert::contains($response, $body);

    $server->shutdown();

    echo "DONE\n";
});
?>
--EXPECT--
DONE
