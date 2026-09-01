--TEST--
swoole_windows: iocp curl
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!extension_loaded('curl')) {
    die('skip curl extension not loaded');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;
use Swoole\Coroutine\Socket;
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

$port = get_one_free_port();
Runtime::enableCoroutine(SWOOLE_HOOK_CURL);

run(function () use ($port) {
    $server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($server->bind('127.0.0.1', $port));
    Assert::true($server->listen());
    go(function () use ($server) {
        $connection = $server->accept();
        Assert::isInstanceOf($connection, Socket::class);
        Assert::contains($connection->recv(), 'GET / HTTP/1.1');
        $connection->sendAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nPONG\n");
        $connection->close();
        $server->close();
    });

    $ch = curl_init('http://127.0.0.1:' . $port . '/');
    Assert::isInstanceOf($ch, Swoole\Curl\Handler::class);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    Assert::same(curl_exec($ch), "PONG\n");
    Assert::same(curl_getinfo($ch, CURLINFO_HTTP_CODE), 200);
    curl_close($ch);
});

echo "DONE\n";
?>
--EXPECT--
DONE
