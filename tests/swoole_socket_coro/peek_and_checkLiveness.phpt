--TEST--
swoole_socket_coro: peek and checkLiveness
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

$pm = new ProcessManager;
$pm->initRandomDataEx(MAX_CONCURRENCY_MID, 1, 1024);
$pm->parentFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        for ($c = MAX_CONCURRENCY_MID; $c--;) {
            Coroutine::create(function () use ($pm, $c) {
                $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
                Assert::true($socket->connect('127.0.0.1', $pm->getFreePort()));
                $random = get_safe_random();
                Assert::same($socket->sendAll($random), strlen($random));
                for ($n = 100; $n--;) {
                    Coroutine::sleep(0.001);
                    $data = $socket->peek(strlen($random));
                    if ($data === $random) {
                        break;
                    }
                }
                Assert::greaterThan($n, 0);
                /* clean the socket buffer */
                $socket->recv();
                /* then we check the liveness */
                Assert::false($socket->checkLiveness());
            });
        }
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function (Swoole\Server $server, int $fd, int $rid, string $data) use ($pm) {
        $server->send($fd, $data);
        $server->close($fd);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
