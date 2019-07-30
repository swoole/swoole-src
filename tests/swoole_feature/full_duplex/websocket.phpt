--TEST--
swoole_feature/full_duplex: websocket
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm, $c) {
            $cli = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => -1]);
            $ret = $cli->upgrade('/');
            Assert::true($ret);
            if ($ret) {
                $randoms = [];
                for ($n = MAX_REQUESTS; $n--;) {
                    $randoms[] = get_safe_random();
                }
                go(function () use ($cli, $randoms) {
                    for ($n = MAX_REQUESTS; $n--;) {
                        $ret = $cli->push(json_encode([$n, $randoms[$n]]));
                        Assert::true($ret);
                    }
                });
                go(function () use ($cli, $randoms) {
                    for ($n = MAX_REQUESTS; $n--;) {
                        $frame = $cli->recv();
                        list($_n, $data) = json_decode($frame->data);
                        Assert::same($randoms[$_n], $data);
                    }
                });
            }
        });
    }
    Swoole\Event::wait();
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set(['log_file' => '/dev/null']);
    $serv->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $serv->on('message', function (Swoole\WebSocket\Server $server, Swoole\WebSocket\Frame $frame) {
        $server->push($frame->fd, $frame->data);
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
