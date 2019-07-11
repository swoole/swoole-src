--TEST--
swoole_client_coro: tcp package length check
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomData(count(tcp_length_types()) * MAX_REQUESTS);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        foreach (tcp_length_types() as $length_type => $type_length) {
            $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $client->set([
                'open_eof_split' => false,
                'open_length_check' => true,
                'package_length_type' => $length_type,
                'package_length_offset' => 0,
                'package_body_offset' => $type_length
            ]);
            if ($client->connect('127.0.0.1', $pm->getFreePort(), 0.1)) {
                for ($n = MAX_REQUESTS; $n--;) {
                    $data = $pm->getRandomData();
                    $recv = substr($client->recv(-1), $type_length);
                    if (!Assert::assert($recv === $data)) {
                        echo "ERROR\n";
                        break;
                    }
                }
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
        $length_type = array_keys(tcp_length_types())[$fd - 1];
        for ($n = MAX_REQUESTS; $n--;) {
            Assert::assert($server->send($fd, tcp_pack($pm->getRandomData(), $length_type)));
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
