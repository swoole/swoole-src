--TEST--
swoole_server: command cancellation, shutdown and late replies settle each wait once
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$gate = new Swoole\Atomic(1);
$ready = new Swoole\Atomic();
$shutdownSettled = false;
$server = new Swoole\Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS);
$server->set(['worker_num' => 1, 'reactor_num' => 1, 'max_wait_time' => 2, 'log_file' => '/dev/null']);
$server->addCommand('echo', SWOOLE_SERVER_COMMAND_EVENT_WORKER | SWOOLE_SERVER_COMMAND_MASTER,
    function ($server, $message) use ($gate) {
        $request = json_decode($message, true);
        if (!empty($request['block'])) {
            $deadline = microtime(true) + 5;
            while (!$gate->get() && microtime(true) < $deadline) { usleep(1000); }
            Assert::same($gate->get(), 1);
        }
        return $message;
    });
$server->on('WorkerStart', function () use ($ready) { $ready->set(1); });
$server->on('Receive', function () {});
$server->on('Start', function ($server) use ($gate, $ready, &$shutdownSettled) {
    Assert::same((new ReflectionMethod($server, 'command'))->getNumberOfParameters(), 5);
    $deadline = microtime(true) + 5;
    while (!$ready->get() && microtime(true) < $deadline) { Co::sleep(0.001); }
    Assert::same($ready->get(), 1);

    $gate->set(0);
    $cancelled = false;
    $cid = go(function () use ($server, &$cancelled) {
        Assert::false($server->command('echo', 0, SWOOLE_SERVER_COMMAND_EVENT_WORKER, ['block' => true], false));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
        $cancelled = true;
    });
    Assert::true(Co::cancel($cid));
    Assert::true($cancelled);
    $gate->set(1);
    Assert::same($server->command('echo', 0, SWOOLE_SERVER_COMMAND_EVENT_WORKER, ['id' => 1], false), '{"id":1}');

    $gate->set(0);
    go(function () use ($server, &$shutdownSettled) {
        Assert::false($server->command('echo', 0, SWOOLE_SERVER_COMMAND_EVENT_WORKER, ['block' => true], false));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
        Assert::false($server->command('echo', 0, SWOOLE_SERVER_COMMAND_MASTER, []));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_WRONG_OPERATION);
        $shutdownSettled = true;
    });
    Assert::true($server->shutdown());
});
$server->on('BeforeShutdown', function () use ($gate) { $gate->set(1); });
$server->start();
Assert::true($shutdownSettled);
echo "DONE\n";
?>
--EXPECT--
DONE
