--TEST--
swoole_socket_coro: readv test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

use Swoole\Coroutine\Socket;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

use function Swoole\Coroutine\run;

require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $conn = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        $conn->connect('127.0.0.1', $pm->getFreePort());
        $conn->send('hello');
        $iov = [[5], [5]];
        $conn->readv($iov);
        Assert::same($iov[0][1], 'hello');
        Assert::same($iov[1][1], 'world');
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);

        $server->handle(function (Connection $conn) use ($server) {
            $conn->send("helloworld\n");
            $conn->close();

            $server->shutdown();
        });

        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
