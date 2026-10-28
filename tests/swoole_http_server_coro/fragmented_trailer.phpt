--TEST--
swoole_http_server_coro: preserve fragmented trailer fields
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Socket;

Coroutine\run(function () {
    $server  = new Server('127.0.0.1', 0);
    $headers = [];
    $server->handle('/', function ($request, $response) use (&$headers) {
        $headers = $request->header;
        $response->end('DONE');
    });
    $cid = Coroutine::create(fn () => $server->start());

    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $server->port, 2));
    $request = "POST / HTTP/1.1\r\n"
        . "Host: localhost\r\n"
        . "Transfer-Encoding: chunked\r\n"
        . "Connection: close\r\n\r\n"
        . "1\r\na\r\n0\r\n";
    Assert::same($socket->sendAll($request, 2), strlen($request));
    foreach (str_split("X-Trailer: yes\r\nX-Empty:\r\n\r\n") as $byte) {
        Assert::same($socket->sendAll($byte, 2), 1);
        Coroutine::sleep(0.001);
    }
    Assert::contains($socket->recv(8192, 2), 'DONE');

    Assert::same($headers['x-trailer'] ?? null, 'yes');
    Assert::same($headers['x-empty'] ?? null, '');
    $socket->close();
    $server->shutdown();
    Coroutine::join([$cid]);
});
echo "DONE\n";
?>
--EXPECT--
DONE
