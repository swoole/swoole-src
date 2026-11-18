--TEST--
swoole_server: pausing in onReceive with the EOF protocol must neither redeliver the packet nor close the connection
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([false, true] as $split) {
    $pm = new SwooleTest\ProcessManager;
    $pm->parentFunc = function (int $pid) use ($pm, $split) {
        Swoole\Coroutine\run(function () use ($pm) {
            $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            Assert::true($cli->connect('127.0.0.1', $pm->getFreePort(), 1));
            foreach (['a', 'b', 'c'] as $item) {
                $cli->send("$item\r\n");
                Assert::same($cli->recv(2), "$item\r\n");
                Co::sleep(0.2);
            }
            $cli->close();
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $split) {
        $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
        $serv->set([
            'open_eof_check' => true,
            'open_eof_split' => $split,
            'package_eof' => "\r\n",
            'worker_num' => 1,
            'log_file' => '/dev/null',
        ]);
        $serv->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $serv->on('Receive', function (Swoole\Server $serv, int $fd, int $rid, string $data) {
            $serv->pause($fd);
            $serv->send($fd, $data);
            Swoole\Timer::after(50, fn() => $serv->resume($fd));
        });
        $serv->start();
    };
    $pm->childFirst();
    $pm->run();
    $pm->kill();
}
echo "DONE\n";
?>
--EXPECT--
DONE
