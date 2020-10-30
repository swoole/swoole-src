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
        $iov = [5, 5];
        $ret = $conn->readVector($iov);
        Assert::same($ret, ['hello', 'world']);

        $conn->send('hello');
        $iov = [5, 7];
        $ret = $conn->readVector($iov);
        Assert::same($ret, ['hello', 'world']);

        $conn->send('hello');
        $iov = [5, 7, 7];
        $ret = $conn->readVector($iov);
        Assert::same($ret, ['hello', 'world']);
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);

        $server->handle(function (Connection $conn) use ($server) {
            while (true) {
                $conn->recv();
                $conn->send("helloworld");
            }
        });

        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
