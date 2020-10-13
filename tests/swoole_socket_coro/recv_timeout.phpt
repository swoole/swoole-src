--TEST--
swoole_socket_coro: recv timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm) {
            $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            Assert::assert($conn->connect('127.0.0.1', $pm->getFreePort()));
            $conn->send(json_encode(['data' => 'hello']));
            $timeout = ms_random(0.1, 1);
            $s = microtime(true);
            $case = mt_rand(0, 2);
            switch ($case) {
                case 0:
                    $ret = $conn->recv(1024, $timeout);
                    break;
                case 1:
                    $ret = $conn->recvAll(1024, $timeout);
                    break;
                case 2:
                    $ret = $conn->recvfrom($peer, $timeout);
                    break;
            }
            time_approximate($timeout, microtime(true) - $s);
            Assert::assert($ret === false, "[case=$case]");
            Assert::assert($conn->errCode == SOCKET_ETIMEDOUT);
        });
    }
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
