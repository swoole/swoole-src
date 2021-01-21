--TEST--
swoole_socket_coro: recv line
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

Co\run(function () {
    $port = get_one_free_port();
    go(function() use($port) {
        $server = new Server('0.0.0.0', $port, false);

        $server->handle(function (Connection $conn) use ($server) {
            $conn->send("hello world\n");
            $conn->send("\r");
            $conn->send(str_repeat('A', 128) . str_repeat('B', 125));
            $server->shutdown();
        });

        $server->start();
    });

    $cli = new Co\Socket(AF_INET, SOCK_STREAM, 0);
    if ($cli->connect('127.0.0.1', $port) == false) {
        echo "ERROR\n";
        return;
    }
    Assert::eq($cli->recvLine(128), "hello world\n");
    Assert::eq($cli->recvLine(128), "\r");
    Assert::eq($cli->recvLine(128), str_repeat('A', 128));
    Assert::eq($cli->recvLine(128), str_repeat('B', 125));
    Assert::eq($cli->recvLine(128), "");
});

?>
--EXPECT--
