--TEST--
swoole_server: BASE worker shutdown settles its pending command before WorkerStop
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$gate = new Swoole\Atomic();
$ready = new Swoole\Atomic();
$settled = new Swoole\Atomic();
$server = new Swoole\Server('127.0.0.1', get_one_free_port(), SWOOLE_BASE);
$server->set(['worker_num' => 2, 'max_wait_time' => 2, 'log_file' => '/dev/null']);
$server->addCommand('blocked', SWOOLE_SERVER_COMMAND_EVENT_WORKER, function () use ($gate) {
    $deadline = microtime(true) + 5;
    while (!$gate->get() && microtime(true) < $deadline) { usleep(1000); }
    Assert::same($gate->get(), 1);
    return 'result';
});
$server->on('Receive', function () {});
$server->on('BeforeShutdown', function () use ($gate) { $gate->set(1); });
$server->on('WorkerStart', function ($server, $id) use ($ready, $settled, $gate) {
    if ($id === 1) { $ready->set(1); return; }
    $deadline = microtime(true) + 5;
    while (!$ready->get() && microtime(true) < $deadline) { Co::sleep(0.001); }
    Assert::same($ready->get(), 1);
    go(function () use ($server, $settled, $gate) {
        Assert::false($server->command('blocked', 1, SWOOLE_SERVER_COMMAND_EVENT_WORKER, [], false));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
        $settled->set(1);
        $gate->set(1);
    });
    Swoole\Timer::after(1, function () use ($server) { $server->shutdown(); });
});
$server->on('WorkerStop', function ($server, $id) use ($settled) {
    if ($id === 0) { Assert::same($settled->get(), 1); }
});
$server->start();
Assert::same($settled->get(), 1);
echo "DONE\n";
?>
--EXPECT--
DONE
