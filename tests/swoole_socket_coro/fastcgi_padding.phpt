--TEST--
swoole_socket_coro: maximum FastCGI content length and padding are independent
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Swoole\Coroutine\Socket;

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $server->handle(function (Connection $connection) {
        foreach ([[0, 255], [65534, 2], [65535, 0], [65535, 1], [65535, 255]] as [$length, $padding]) {
            $frame = pack('CCnnCC', 1, 6, 1, $length, $padding, 0)
                . str_repeat('x', $length) . str_repeat("\0", $padding);
            // Split the header, then the content, to exercise incremental framing too.
            $connection->send(substr($frame, 0, 3));
            Coroutine::sleep(0.001);
            $connection->send(substr($frame, 3, 8192));
            if (strlen($frame) > 8195) {
                $connection->send(substr($frame, 8195));
            }
        }
        $connection->close();
    });
    Coroutine::create(fn () => $server->start());
    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    $socket->setProtocol(['open_fastcgi_protocol' => true]);
    Assert::true($socket->connect('127.0.0.1', $server->port));
    foreach ([[0, 255], [65534, 2], [65535, 0], [65535, 1], [65535, 255]] as [$length, $padding]) {
        $expected = pack('CCnnCC', 1, 6, 1, $length, $padding, 0)
            . str_repeat('x', $length) . str_repeat("\0", $padding);
        Assert::same($socket->recvPacket(1), $expected);
    }
    $socket->close();
    $server->shutdown();
});
echo "DONE\n";
?>
--EXPECT--
DONE
