--TEST--
swoole_server: shutdown does not resume an inline command handler's unrelated coroutine wait
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$completed = false;
$server = new Swoole\Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS);
$server->set(['worker_num' => 1, 'reactor_num' => 1, 'max_wait_time' => 2, 'log_file' => '/dev/null']);
$server->addCommand('local', SWOOLE_SERVER_COMMAND_MASTER, function ($server) {
    $channel = new Swoole\Coroutine\Channel(1);
    Swoole\Timer::after(1, function () use ($server) { $server->shutdown(); });
    Swoole\Timer::after(20, function () use ($channel) { $channel->push('ready'); });
    // The command's error callback must not resume this unrelated Channel::pop() during shutdown.
    Assert::same($channel->pop(), 'ready');
    return 'result';
});
$server->on('Receive', function () {});
$server->on('Start', function ($server) use (&$completed) {
    Assert::false($server->command('local', 0, SWOOLE_SERVER_COMMAND_MASTER, [], false));
    Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
    $completed = true;
});
$server->start();
Assert::true($completed);
echo "DONE\n";
?>
--EXPECT--
DONE
