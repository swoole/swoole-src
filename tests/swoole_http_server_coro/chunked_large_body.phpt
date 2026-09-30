--TEST--
swoole_http_server_coro: enforce chunked request package limits
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

function make_chunked_request(string $path, string $body): string
{
    return "POST {$path} HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        dechex(strlen($body)) . "\r\n{$body}\r\n0\r\n\r\n";
}

function send_chunked_request(Server $server, string $request): string
{
    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $server->port, -1));
    $socket->sendAll($request);

    $response = '';
    while (($data = $socket->recv()) !== '' && $data !== false) {
        $response .= $data;
    }
    return $response;
}

function start_http_server(int $limit, callable $handler): Server
{
    $server = new Server('127.0.0.1', 0);
    $server->set(['package_max_length' => $limit]);
    Coroutine::create(function () use ($server, $handler) {
        $server->handle('/', $handler);
        $server->start();
    });
    Coroutine::sleep(0.001);
    return $server;
}

Coroutine\run(function () {
    $handled = 0;
    $receivedLength = 0;
    $receivedHash = '';
    $server = start_http_server(
        300000,
        function (Request $request, Response $response) use (
            &$handled,
            &$receivedLength,
            &$receivedHash
        ) {
            $handled++;
            $content = $request->rawContent();
            $receivedLength = strlen($content);
            $receivedHash = md5($content);
            $response->end('OK');
        }
    );

    $body = str_repeat('0123456789abcdef', 17500);
    $successResponse = send_chunked_request($server, make_chunked_request('/', $body));
    $largeResponse = send_chunked_request($server, make_chunked_request('/', str_repeat('B', 320000)));
    $server->shutdown();

    Assert::contains($successResponse, 'HTTP/1.1 200 OK');
    Assert::same($receivedLength, strlen($body));
    Assert::same($receivedHash, md5($body));
    Assert::contains($largeResponse, 'HTTP/1.1 413 Payload Too Large');
    Assert::same($handled, 1);

    $exactBody = str_repeat('E', 7000);
    $exactRequest = make_chunked_request('/', $exactBody);
    $limit = strlen($exactRequest);
    $handled = 0;
    $receivedLength = 0;
    $server = start_http_server(
        $limit,
        function (Request $request, Response $response) use (&$handled, &$receivedLength) {
            $handled++;
            $receivedLength = strlen($request->rawContent());
            $response->end('OK');
        }
    );

    $exactResponse = send_chunked_request($server, $exactRequest);
    $overResponse = send_chunked_request($server, make_chunked_request('/', $exactBody . 'X'));
    $overflowResponse = send_chunked_request(
        $server,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 18446744073709551615\r\nConnection: close\r\n\r\n"
    );
    $headerResponse = send_chunked_request(
        $server,
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Fill: " . str_repeat('H', $limit) . "\r\nConnection: close\r\n\r\n"
    );
    $server->shutdown();

    Assert::contains($exactResponse, 'HTTP/1.1 200 OK');
    Assert::same($receivedLength, strlen($exactBody));
    Assert::contains($overResponse, 'HTTP/1.1 413 Payload Too Large');
    Assert::contains($overflowResponse, 'HTTP/1.1 413 Payload Too Large');
    Assert::contains($headerResponse, 'HTTP/1.1 413 Payload Too Large');
    Assert::same($handled, 1);

    echo "DONE\n";
});
?>
--EXPECT--
DONE
