--TEST--
swoole_server: idle shutdown sends FIN before onClose returns when paused reads hide peer EOF
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $allowClose = new Swoole\Atomic();
    $closes = new Swoole\Atomic();
    $pm = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $allowClose, $closes) {
        $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 3);
        stream_set_timeout($client, 3);
        fwrite($client, 'begin');
        Assert::same(fgets($client), "ready\n");
        Assert::true(stream_socket_shutdown($client, STREAM_SHUT_WR));
        // onClose cannot return until this EOF has arrived, so close() cannot supply FIN.
        Assert::same(stream_get_contents($client), '');
        Assert::false(stream_get_meta_data($client)['timed_out']);
        Assert::same($closes->get(), 0);
        $allowClose->set(1);
        $deadline = microtime(true) + 3;
        while ($closes->get() === 0 && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($closes->get(), 1);
        fclose($client);
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $allowClose, $closes, $mode) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'reactor_num' => 1,
            'enable_coroutine' => false,
            'max_idle_time' => 0.2,
            'log_file' => '/dev/null',
        ]);
        $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('receive', function ($server, $fd) {
            Assert::true($server->pause($fd));
            Assert::true($server->send($fd, "ready\n"));
        });
        $server->on('close', function () use ($allowClose, $closes) {
            $deadline = microtime(true) + 5;
            while ($allowClose->get() === 0 && microtime(true) < $deadline) {
                usleep(1000);
            }
            Assert::same($closes->add(), 1);
        });
        $server->start();
    };
    $pm->setWaitTimeout(10);
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
