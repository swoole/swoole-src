--TEST--
swoole_server: max_idle_time keeps receive-only, send-only and bidirectional traffic alive
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new SwooleTest\ProcessManager();
    $closed = new Swoole\Atomic();
    $pm->parentFunc = function () use ($pm, $closed) {
        foreach (['echo', 'receive', 'send'] as $direction) {
            $client = new Swoole\Client(SWOOLE_SOCK_TCP);
            $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
            $client->send($direction . "\n");
            Assert::same($client->recv(), "ready\n");
            $start = microtime(true);
            while (microtime(true) - $start < 0.8) {
                if ($direction !== 'send') {
                    Assert::same($client->send("x\n"), 2);
                }
                if ($direction !== 'receive') {
                    Assert::same($client->recv(), "x\n");
                }
                Assert::same($closed->get(), 0);
                usleep(20000);
            }
            $client->send("stop\n");
            // Drain any ticks sent before the server handles "stop", then require EOF.
            while (($data = $client->recv()) !== '') {
                Assert::same($data, "x\n");
            }
            $client->close();
            // EOF can precede the worker callback by a scheduling interval.
            $deadline = microtime(true) + 3;
            while ($closed->get() === 0 && microtime(true) < $deadline) {
                usleep(1000);
            }
            Assert::same($closed->get(), 1);
            $closed->set(0);
        }
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $closed, $mode) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'reactor_num' => 1,
            'log_file' => '/dev/null',
            'max_idle_time' => 0.3,
            'enable_coroutine' => false,
            'open_eof_check' => true,
            'package_eof' => "\n",
        ]);
        $timers = [];
        $directions = [];
        $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('receive', function ($server, $fd, $reactor, $data) use (&$directions, &$timers) {
            $data = trim($data);
            if (!isset($directions[$fd])) {
                $directions[$fd] = $data;
                $server->send($fd, "ready\n");
                if ($data === 'send') {
                    $timers[$fd] = Swoole\Timer::tick(40, function () use ($server, $fd) {
                        $server->send($fd, "x\n");
                    });
                }
            } elseif ($data === 'stop') {
                if (isset($timers[$fd])) {
                    Swoole\Timer::clear($timers[$fd]);
                    unset($timers[$fd]);
                }
            } elseif ($directions[$fd] === 'echo') {
                $server->send($fd, $data . "\n");
            }
        });
        $server->on('close', function ($server, $fd) use ($closed, &$directions) {
            unset($directions[$fd]);
            $closed->add();
        });
        $server->start();
    };
    $pm->setWaitTimeout(15);
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
