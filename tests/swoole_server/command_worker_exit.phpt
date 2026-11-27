--TEST--
swoole_server: a command remains pending after target exit until its administrator cancels it
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$executed = new Swoole\Atomic();
$server = new Swoole\Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS);
$server->set(['worker_num' => 1, 'reactor_num' => 1, 'log_file' => '/dev/null']);
$server->addCommand('exit', SWOOLE_SERVER_COMMAND_EVENT_WORKER, function () use ($executed) {
    $executed->add();
    Swoole\Process::kill(getmypid(), SIGKILL);
    return '';
});
$server->on('Receive', function () {});
$server->on('Start', function ($server) use ($executed) {
    $settled = false;
    $cid = go(function () use ($server, &$settled) {
        Assert::false($server->command('exit', 0, SWOOLE_SERVER_COMMAND_EVENT_WORKER, []));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
        $settled = true;
    });
    $deadline = microtime(true) + 5;
    while (!$executed->get() && microtime(true) < $deadline) { Co::sleep(0.001); }
    Assert::same($executed->get(), 1);
    Assert::false($settled);
    Assert::true(Co::cancel($cid));
    Assert::true($settled);
    $server->shutdown();
});
$server->start();
echo "DONE\n";
?>
--EXPECT--
DONE
