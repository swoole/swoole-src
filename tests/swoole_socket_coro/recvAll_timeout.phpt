--TEST--
swoole_socket_coro: recvAll timeout (slow network)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomDataEx(MAX_CONCURRENCY_MID, 1, 1024);
$pm->parentFunc = function ($pid) use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm, $c) {
            $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            Assert::assert($conn->connect('127.0.0.1', $pm->getFreePort()));
            $conn->send($c);
            $timeout = ms_random(0.1, 1);
            $s = microtime(true);
            $data = $conn->recvAll(1024, $timeout);
            time_approximate($timeout, microtime(true) - $s);
            Assert::assert(strlen($data) > 0);
            Assert::assert(strlen($data) != 1024);
            Assert::assert(strpos($pm->getRandomDataEx($c), $data) === 0);
            Assert::assert($conn->errCode == SOCKET_ETIMEDOUT);
            Assert::assert($conn->errMsg == swoole_strerror(SOCKET_ETIMEDOUT));
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
    $server->on('Receive', function (Swoole\Server $server, int $fd, int $rid, string $data) use ($pm) {
        $s = $pm->getRandomDataEx($data);
        while ($server->exists($fd)) {
            $server->send($fd, string_pop_front($s, 1));
            Co::sleep(0.005);
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
