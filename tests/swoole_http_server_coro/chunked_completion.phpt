--TEST--
swoole_http_server_coro: parse chunked request completion exactly
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

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $handled = 0;
    $requests = [];

    Coroutine::create(function () use ($server, &$handled, &$requests) {
        $server->handle('/', function (Request $request, Response $response) use (&$handled, &$requests) {
            $handled++;
            $requests[] = [
                'path' => '/',
                'content' => $request->rawContent(),
                'data' => $request->getData(),
                'trailer' => $request->header['x-trailer'] ?? null,
            ];
            $response->end('FIRST');
        });
        $server->handle('/next', function (Request $request, Response $response) use (&$handled, &$requests) {
            $handled++;
            $requests[] = ['path' => '/next', 'data' => $request->getData()];
            $response->end('SECOND');
        });
        $server->handle('/encoded', function (Request $request, Response $response) use (&$handled, &$requests) {
            $handled++;
            $requests[] = ['path' => '/encoded', 'content' => $request->rawContent()];
            $response->end('ENCODED');
        });
        $server->start();
    });
    Coroutine::sleep(0.001);

    $payload = str_repeat('A', hexdec('1fa'));
    $header = "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n";
    $first = $header . "5\r\n0\r\n\r\n";
    $second = "\r\n1f";
    $third = "a\r\n{$payload}\r\n0\r\nX-Trailer: yes\r\n\r\n";
    $chunkedRequest = $first . $second . $third;
    $pipelineRequest = "GET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $server->port, -1));
    Assert::same($socket->sendAll($first), strlen($first));
    Coroutine::sleep(0.05);
    Assert::same($handled, 0);
    Assert::same($socket->sendAll($second), strlen($second));
    Coroutine::sleep(0.01);
    Assert::same($handled, 0);
    Assert::same($socket->sendAll($third . $pipelineRequest), strlen($third . $pipelineRequest));
    $response = recv_all($socket);

    Assert::same(substr_count($response, 'HTTP/1.1 200 OK'), 2);
    Assert::contains($response, 'FIRST');
    Assert::contains($response, 'SECOND');
    Assert::same($requests[0]['path'], '/');
    Assert::same($requests[0]['content'], "0\r\n\r\n" . $payload);
    Assert::same($requests[0]['data'], $chunkedRequest);
    Assert::same($requests[0]['trailer'], 'yes');
    Assert::same($requests[1]['path'], '/next');
    Assert::same($requests[1]['data'], $pipelineRequest);

    $encoded = gzencode(str_repeat('encoded-data-', 8));
    $encodedRequest = "POST /encoded HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: gzip, chunked\r\n" .
        "Connection: close\r\n\r\n" .
        dechex(strlen($encoded)) . "\r\n{$encoded}\r\n0\r\n\r\n";
    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $server->port, -1));
    Assert::same($socket->sendAll($encodedRequest), strlen($encodedRequest));
    $response = recv_all($socket);
    $server->shutdown();

    Assert::contains($response, 'HTTP/1.1 200 OK');
    Assert::contains($response, 'ENCODED');
    Assert::same($requests[2]['path'], '/encoded');
    // This checks chunked framing; Swoole leaves other transfer codings unchanged.
    Assert::same($requests[2]['content'], $encoded);
    Assert::same($handled, 3);

    echo "DONE\n";
});
?>
--EXPECT--
DONE
