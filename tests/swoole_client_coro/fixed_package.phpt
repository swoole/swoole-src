--TEST--
swoole_client_coro: fixed package
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->setRandomFunc('mt_rand');
$pm->initRandomDataEx(1, MAX_REQUESTS, 0, 65535);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $client->set([
            'open_length_check' => true,
            'package_length_func' => function (string $data) {
                if (strlen($data) >= 2) {
                    return 2;
                }
                return 0;
            }
        ]);
        if ($client->connect('127.0.0.1', $pm->getFreePort(), 1)) {
            for ($n = MAX_REQUESTS; $n--;) {
                $data = $client->recv();
                if (!$data) {
                    echo "ERROR\n";
                    break;
                }
                Assert::same($data, pack('n', $pm->getRandomData()));
            }
        }
    });
    swoole_event_wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $server->on('connect', function (Swoole\Server $server, int $fd) use ($pm) {
        for ($n = MAX_REQUESTS; $n--;) {
            $server->send($fd, pack('n', $pm->getRandomData()));
        }
    });
    $server->on('receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
