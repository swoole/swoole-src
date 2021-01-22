--TEST--
swoole_socket_coro: recv with buffer
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

const DATA = "hello world\n";

Co\run(function () {
    $port = get_one_free_port();
    go(function () use ($port) {
        $server = new Server('0.0.0.0', $port, false);

        $server->handle(function (Connection $conn) use ($server) {
            $conn->send(DATA);
            $server->shutdown();
        });

        $server->start();
    });

    $cli = new Co\Socket(AF_INET, SOCK_STREAM, 0);
    if ($cli->connect('127.0.0.1', $port) == false) {
        echo "ERROR\n";
        return;
    }

    $data = '';
    while (1) {
        $char = $cli->recvWithBuffer(1);
        if (strlen($char) == 1) {
            $data .= $char;
        } else {
            break;
        }
    }
    Assert::eq($data, DATA);
});
?>
--EXPECT--
