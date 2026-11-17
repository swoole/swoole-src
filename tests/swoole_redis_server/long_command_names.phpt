--TEST--
swoole_redis_server: long command names remain distinct in registration, lookup and dispatch
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$commands = [
    str_repeat('x', 54) . 'A',
    str_repeat('x', 54) . 'B',
    str_repeat('y', 62) . 'A',
    str_repeat('y', 62) . 'B',
];
$pm = new ProcessManager;
$pm->parentFunc = static function () use ($pm, $commands) {
    Swoole\Coroutine\run(static function () use ($pm, $commands) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        foreach ($commands as $index => $command) {
            // Registration and lookup must agree with the case-insensitive wire spelling.
            $command = strtolower($command);
            $request = '*1' . "\r\n$" . strlen($command) . "\r\n" . $command . "\r\n";
            Assert::same($client->send($request), strlen($request));
            $expected = '+reply-' . $index . "\r\n";
            $reply = '';
            while (strlen($reply) < strlen($expected)) {
                $chunk = $client->recv();
                Assert::notEmpty($chunk);
                $reply .= $chunk;
            }
            Assert::same($reply, $expected);
        }
    });
    $pm->kill();
};
$pm->childFunc = static function () use ($pm, $commands) {
    $server = new Swoole\Redis\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $handlers = [];
    foreach ($commands as $index => $command) {
        $handlers[$index] = static function ($fd) use ($server, $index) {
            $server->send($fd, '+reply-' . $index . "\r\n");
        };
        Assert::true($server->setHandler($command, $handlers[$index]));
    }
    foreach ($commands as $index => $command) {
        Assert::same($server->getHandler(strtolower($command)), $handlers[$index]);
    }
    $server->on('WorkerStart', static function () use ($pm) { $pm->wakeup(); });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
