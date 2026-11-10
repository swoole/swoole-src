--TEST--
swoole_thread/server: connect and close callbacks run once across peer and forwarded close races
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Client;
use Swoole\Server;
use Swoole\Thread;
use Swoole\Timer;
use function Swoole\Coroutine\run;

const CONNECTIONS = 96;
$port = get_constant_port(__FILE__);
$server = new Server('127.0.0.1', $port, SWOOLE_THREAD);
$server->set([
    'worker_num' => 2,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $queue, $ready, $connects, $closes;
        $queue = new Thread\Queue();
        $ready = new Thread\Atomic();
        $connects = new Thread\Atomic();
        $closes = new Thread\Atomic();
        return [$queue, $ready, $connects, $closes];
    },
]);
$seen = [];
$server->on('workerStart', function () {
    [$queue, $ready] = Thread::getArguments();
    if ($ready->add() === 2) {
        $queue->push('ready', Thread\Queue::NOTIFY_ALL);
    }
});
$server->on('connect', function (Server $server, int $fd) use (&$seen) {
    [, , $connects] = Thread::getArguments();
    Assert::false(isset($seen[$fd]));
    $seen[$fd] = 0;
    $connects->add();
});
$server->on('receive', function (Server $server, int $fd, int $reactor, string $data) {
    if ($data === 'hello') {
        Assert::true($server->send($fd, 'ready'));
        return;
    }
    $server->sendMessage([$fd, $data === 'reset'], 1 - $server->getWorkerId());
    Timer::after(1, function () use ($server, $fd) {
        if ($server->exists($fd)) {
            @$server->close($fd);
        }
    });
});
$server->on('pipeMessage', function (Server $server, int $worker, array $message) {
    [$fd, $reset] = $message;
    if ($server->exists($fd)) {
        @$server->close($fd, $reset);
    }
});
$server->on('close', function (Server $server, int $fd) use (&$seen) {
    [, , , $closes] = Thread::getArguments();
    Assert::true(isset($seen[$fd]));
    Assert::same(++$seen[$fd], 1);
    $closes->add();
});
$server->on('shutdown', function () {
    global $connects, $closes;
    Assert::same($connects->get(), CONNECTIONS);
    Assert::same($closes->get(), CONNECTIONS);
    echo "DONE\n";
});
$server->addProcess(new Swoole\Process(function () use ($server, $port) {
    [$queue, , , $closes] = Thread::getArguments();
    Assert::same($queue->pop(5), 'ready');
    run(function () use ($port, $closes) {
        for ($wave = 0; $wave < 3; $wave++) {
            $clients = [];
            for ($i = 0; $i < CONNECTIONS / 3; $i++) {
                $clients[] = go(function () use ($port, $i) {
                    $client = new Client(SWOOLE_SOCK_TCP);
                    Assert::true($client->connect('127.0.0.1', $port, 5));
                    Assert::same($client->send('hello'), 5);
                    Assert::same($client->recv(), 'ready');
                    Assert::same($client->send($i % 2 ? 'reset' : 'close'), 5);
                    if ($i % 3) {
                        Coroutine::sleep(($i % 3) / 1000);
                    }
                    $client->close();
                });
            }
            Coroutine::join($clients);
        }
        $deadline = microtime(true) + 10;
        while ($closes->get() < CONNECTIONS && microtime(true) < $deadline) {
            Coroutine::sleep(0.01);
        }
    });
    $server->shutdown();
}));
$server->start();
?>
--EXPECT--
DONE
