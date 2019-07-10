--TEST--
swoole_client_coro: eof with multi packages
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initRandomData(MAX_REQUESTS);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $client = new Co\Client(SWOOLE_TCP);
        $client->set([
            'open_eof_check' => true,
            'package_eof' => "\r\n",
        ]);
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("ERROR\n");
        }
        go(function () use ($pm, $client) {
            $n = $pm->getRandomDataSize();
            while ($n--) {
                $data = $client->recv();
                if (empty($data)) {
                    break;
                }
                Assert::same(rtrim($data, "\r\n"), $pm->getRandomData());
            }
        });
    });
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $server->set(['log_file' => '/dev/null']);
    $server->on('connect', function (Swoole\Server $server, int $fd) use ($pm) {
        do {
            $data = '';
            for ($n = mt_rand(1, $pm->getRandomDataSize()); $n--;) {
                $data .= $pm->getRandomData() . "\r\n";
            }
            $server->send($fd, $data);
        } while ($pm->getRandomDataSize() > 0);
    });
    $server->on('receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
