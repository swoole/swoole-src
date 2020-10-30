--TEST--
swoole_socket_coro: writev test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $requestLine = "POST / HTTP/1.1\r\n";
        $header = "Host: 127.0.0.1\r\n";
        $header .= "Connection: keep-alive\r\n";
        $header .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n";
        $header .= "Content-Length: 5\r\n";
        $header .= "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36\r\n";
        $header .= "\r\n";

        $body = 'hello';

        $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        $conn->connect('127.0.0.1', $pm->getFreePort());
        $ret = $conn->writeVector([$requestLine, $header, $body]);
        Assert::same($ret, strlen($requestLine) + strlen($header) + strlen($body));
        $ret = $conn->recv();
        Assert::contains($ret, 'world');
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/', function (Request $request, Response $response) {
            Assert::same($request->getContent(), 'hello');
            $response->end('world');
        });

        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
