--TEST--
swoole_thread/server: send WorkerStop and PHP shutdown data before final pipe release
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

Assert::setThrowException(true);

const PAYLOAD_SIZE = 8192;
$port = get_constant_port(__FILE__);
$server = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$server->set([
    'worker_num' => 3,
    'reload_async' => false,
    'max_wait_time' => 2,
    'enable_coroutine' => false,
    'log_file' => '/dev/null',
    'log_level' => SWOOLE_LOG_ERROR,
    'open_eof_check' => true,
    'package_eof' => "\n",
    'init_arguments' => function () {
        global $ready, $target, $phase, $senderTid;
        $ready = new Thread\Atomic();
        $target = new Thread\Atomic();
        $phase = new Thread\Atomic();
        $senderTid = new Thread\Atomic();
        return [$ready, $target, $phase, $senderTid];
    },
]);
$server->on('WorkerStart', function (Swoole\Server $server, int $workerId) {
    [$ready, $target, , $senderTid] = Thread::getArguments();
    if ($workerId === 0) {
        $senderTid->set(Thread::getNativeId());
        register_shutdown_function(function () use ($server, $target) {
            Assert::true($server->send($target->get(), str_repeat('p', PAYLOAD_SIZE)));
        });
    }
    $ready->add();
});
$server->on('WorkerStop', function (Swoole\Server $server, int $workerId) {
    [, $target] = Thread::getArguments();
    if ($workerId === 0) {
        Assert::true($server->send($target->get(), str_repeat('w', PAYLOAD_SIZE)));
    }
});
$server->on('Receive', function (Swoole\Server $server, int $fd, int $reactorId, string $data) {
    [, $target, $phase] = Thread::getArguments();
    if (trim($data) === 'owner') {
        $server->send($fd, $server->worker_id . "\n");
        return;
    }
    $target->set($fd);
    $phase->set(1);
    while ($phase->get() === 1) {
        usleep(1000);
    }
});
$server->on('Shutdown', function () {
    echo "shutdown\n";
});
$server->addProcess(new Swoole\Process(function () use ($server, $port) {
    [$ready, , $phase, $senderTid] = Thread::getArguments();
    $wait = function (callable $condition) {
        for ($i = 0; $i < 500 && !$condition(); $i++) {
            usleep(10_000);
        }
        Assert::true($condition());
    };
    $wait(fn () => $ready->get() === 3);
    $clients = [];
    $targetClient = null;
    for ($i = 0; $i < 20; $i++) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $port, 5));
        $clients[] = $client;
        Assert::greaterThan($client->send("owner\n"), 0);
        if ((int) trim($client->recv()) === 1) {
            $targetClient = $client;
            break;
        }
    }
    Assert::notNull($targetClient);
    Assert::greaterThan($targetClient->send("block\n"), 0);
    $wait(fn () => $phase->get() === 1);
    Assert::true($server->shutdown());

    // Keep the destination's connection alive until the sender has finished its complete PHP
    // request shutdown and native cleanup. /proc avoids a fixed sleep or a premature PHP callback signal.
    $wait(function () use ($senderTid) {
        clearstatcache();
        return !is_dir('/proc/self/task/' . $senderTid->get());
    });
    $phase->set(2);

    $expected = str_repeat('w', PAYLOAD_SIZE) . str_repeat('p', PAYLOAD_SIZE);
    $received = '';
    while (strlen($received) < strlen($expected)) {
        $chunk = $targetClient->recv();
        Assert::notEmpty($chunk);
        $received .= $chunk;
    }
    Assert::same($received, $expected);
    foreach ($clients as $client) {
        $client->close();
    }
    echo "delivered\n";
}));
$server->start();
?>
--EXPECT--
delivered
shutdown
