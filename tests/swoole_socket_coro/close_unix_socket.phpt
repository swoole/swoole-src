--TEST--
swoole_socket_coro: release a bound unix socket path when it is closed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

const SOCKET_PATH = '/tmp/swoole-close-unix-socket.sock';

function bind_unix(int $type): Socket
{
    $socket = new Socket(AF_UNIX, $type, 0);
    Assert::true($socket->bind(SOCKET_PATH));
    if ($type === SOCK_STREAM) {
        Assert::true($socket->listen());
    }
    return $socket;
}

function assert_usable(Socket $socket, int $type): void
{
    Coroutine::sleep(0.01);
    $client = new Socket(AF_UNIX, $type, 0);
    if ($type === SOCK_STREAM) {
        Assert::true($client->connect(SOCKET_PATH));
        Assert::isInstanceOf($socket->accept(1), Socket::class);
    } else {
        Assert::same($client->sendto(SOCKET_PATH, 0, 'hello'), 5);
        Assert::same($socket->recvfrom($peer, 1), 'hello');
    }
}

@unlink(SOCKET_PATH);

Coroutine\run(function () {
    foreach ([SOCK_STREAM, SOCK_DGRAM] as $type) {
        $socket = bind_unix($type);
        Assert::true($socket->close());
        $replacement = bind_unix($type);
        unset($socket);
        assert_usable($replacement, $type);

        unset($replacement);
        Coroutine::sleep(0.01);
        $replacement = bind_unix($type);
        assert_usable($replacement, $type);
        Assert::true($replacement->close());
    }
});
echo "DONE\n";
?>
--CLEAN--
<?php
@unlink('/tmp/swoole-close-unix-socket.sock');
?>
--EXPECT--
DONE
