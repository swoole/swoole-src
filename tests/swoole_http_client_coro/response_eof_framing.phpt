--TEST--
swoole_http_client_coro: EOF only completes close-delimited responses
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;

Coroutine\run(function () {
    $close = "HTTP/1.1 200 OK\r\nConnection: close\r\n";
    $cases = [
        'short content-length' => [$close . "Content-Length: 20\r\n\r\nshort", null],
        'missing content-length body' => [$close . "Content-Length: 1\r\n\r\n", null],
        'short HTTP/1.0 body' => ["HTTP/1.0 200 OK\r\nContent-Length: 20\r\n\r\nshort", null],
        'incomplete chunk' => [$close . "Transfer-Encoding: chunked\r\n\r\n8\r\npart", null],
        'missing final chunk' => [$close . "Transfer-Encoding: chunked\r\n\r\n8\r\ncomplete\r\n", null],
        'incomplete trailers' => [$close . "Transfer-Encoding: chunked\r\n\r\n0\r\nX-Test: value\r\n", null],
        'incomplete headers' => [$close . "Content-Length: 0\r\n", null],
        'complete content-length' => [$close . "Content-Length: 8\r\n\r\ncomplete", 'complete'],
        'complete chunked' => [$close . "Transfer-Encoding: chunked\r\n\r\n8\r\ncomplete\r\n0\r\n\r\n", 'complete'],
        'empty content-length' => [$close . "Content-Length: 0\r\n\r\n", ''],
        'close-delimited' => [$close . "\r\ncomplete", 'complete'],
        'empty close-delimited' => [$close . "\r\n", ''],
        'HTTP/1.0 close-delimited' => ["HTTP/1.0 200 OK\r\n\r\ncomplete", 'complete'],
    ];

    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $port = $listener->getsockname()['port'];

    foreach ([false, true] as $fragmented) {
        foreach ([false, true] as $defer) {
            foreach ($cases as $name => [$response, $expectedBody]) {
                Coroutine::create(function () use ($listener, $response, $fragmented) {
                    $peer = $listener->accept(2);
                    Assert::true($peer instanceof Socket);
                    $request = '';
                    while (!str_contains($request, "\r\n\r\n")) {
                        $data = $peer->recv(8192, 2);
                        Assert::notEmpty($data);
                        $request .= $data;
                    }
                    $parts = $fragmented ? str_split($response, 7) : [$response];
                    foreach ($parts as $part) {
                        Assert::same($peer->sendAll($part), strlen($part));
                        if ($fragmented) {
                            Coroutine::sleep(0.001);
                        }
                    }
                    Assert::true($peer->close());
                });

                $client = new Client('127.0.0.1', $port);
                $client->set(['timeout' => 2]);
                $client->setDefer($defer);
                $result = $client->get('/');
                if ($defer) {
                    Assert::true($result, $name);
                    $result = $client->recv();
                }
                if ($expectedBody === null) {
                    Assert::false($result, $name);
                    Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET, $name);
                    Assert::same($client->errCode, SOCKET_ECONNRESET, $name);
                    Assert::false($client->connected, $name);
                } else {
                    Assert::true($result, $name);
                    Assert::same($client->statusCode, 200, $name);
                    Assert::same($client->body, $expectedBody, $name);
                }
                $client->close();
            }
        }
    }
    Assert::true($listener->close());
});
echo "DONE\n";
?>
--EXPECT--
DONE
