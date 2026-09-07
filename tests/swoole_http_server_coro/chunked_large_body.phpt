--TEST--
swoole_http_server_coro: receive a large chunked request body
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

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $server->set(['package_max_length' => 300000]);

    $handled = 0;
    $receivedLength = 0;
    $receivedHash = '';

    Coroutine::create(function () use ($server, &$handled, &$receivedLength, &$receivedHash) {
        $server->handle('/', function (Request $request, Response $response) use (
            &$handled,
            &$receivedLength,
            &$receivedHash
        ) {
            $handled++;
            $content = $request->rawContent();
            $receivedLength = strlen($content);
            $receivedHash = md5($content);
            $response->end('OK');
        });
        $server->start();
    });
    Coroutine::sleep(0.001);

    $body = str_repeat('0123456789abcdef', 17500);
    $successResponse = send_chunked_request($server, make_chunked_request('/', $body));
    $largeResponse = send_chunked_request($server, make_chunked_request('/', str_repeat('B', 320000)));
    $server->shutdown();

    Assert::contains($successResponse, 'HTTP/1.1 200 OK');
    Assert::same($receivedLength, strlen($body));
    Assert::same($receivedHash, md5($body));
    Assert::contains($largeResponse, 'HTTP/1.1 413 Payload Too Large');
    Assert::same($handled, 1);

    echo "DONE\n";
});
?>
--EXPECT--
DONE
