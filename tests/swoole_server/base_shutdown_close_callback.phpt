--TEST--
swoole_server: BASE shutdown dispatches onClose before WorkerStop and bounds graceful callbacks
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([0, 1, 2] as $case) {
    $closes = new Swoole\Atomic();
    $completed = new Swoole\Atomic();
    $pm = new ProcessManager();
    $pm->childFunc = function () use ($pm, $closes, $completed, $case) {
        // A deliberately unfinished callback tests the hard exit deadline.
        Swoole\Coroutine::set(['enable_deadlock_check' => false]);
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
        $server->set(['worker_num' => 1, 'reload_async' => $case > 0,
            'max_wait_time' => 1, 'log_file' => '/dev/null']);
        $receiving = false;
        $server->on('WorkerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('Receive', function ($server) use (&$receiving) {
            $receiving = true;
            Assert::true($server->shutdown());
            $receiving = false;
        });
        $server->on('Close', function () use (&$receiving, $closes, $completed, $case) {
            Assert::false($receiving);
            Assert::same($closes->add(), 1);
            if ($case > 0) {
                Swoole\Coroutine::sleep($case === 2 ? 60 : 0.01);
                $completed->add();
            }
        });
        $server->on('WorkerStop', function () use ($closes) { Assert::same($closes->get(), 1); });
        $server->start();
    };
    $pm->parentFunc = function () use ($pm) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        Assert::same($client->send('shutdown'), 8);
        // Reset close may return false instead of EOF.
        Assert::true(@$client->recv() === '' || $client->errCode === SOCKET_ECONNRESET);
        $client->close();
    };
    $pm->childFirst();
    $start = microtime(true);
    $pm->run();
    Assert::lessThan(microtime(true) - $start, 8);
    Assert::same($closes->get(), 1);
    Assert::same($completed->get(), $case === 1 ? 1 : 0);
}
echo "DONE\n";
?>
--EXPECT--
DONE
