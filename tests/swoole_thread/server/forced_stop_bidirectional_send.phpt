--TEST--
swoole_thread/server: workers with bidirectional queued writes can stop together
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

const QUEUED_BYTES = 4 * 1024 * 1024;

Swoole\Coroutine::set(['socket_write_timeout' => 0]);

$port = get_constant_port(__FILE__);

$serv = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set([
    'worker_num'       => 3,
    'reload_async'     => false,
    'enable_coroutine' => false,
    'log_level'        => SWOOLE_LOG_ERROR,
    'log_file'         => '/dev/null',
    'open_eof_check'   => true,
    'package_eof'      => "\n",
    'init_arguments'   => function () {
        global $phase, $workerStarts;
        $phase = new Thread\Atomic(0);
        $workerStarts = new Thread\Atomic(0);
        return [$phase, $workerStarts];
    },
]);
$serv->on('WorkerStart', function () {
    [, $workerStarts] = Thread::getArguments();
    $workerStarts->add();
});
$serv->on('Receive', function (Swoole\Server $serv, int $fd, int $reactorId, string $data) {
    [$phase] = Thread::getArguments();
    $request = trim($data);

    if ($request === 'owner') {
        $owner = $serv->getClientInfo($fd)['reactor_id'];
        $serv->send($fd, "{$owner}:{$fd}\n");
        return;
    }

    $target = (int) substr($request, strlen('stop:'));
    Assert::true($serv->stop());
    $phase->add();
    while ($phase->get() < 2) {
        usleep(1000);
    }

    Assert::true($serv->send($target, str_repeat('x', QUEUED_BYTES)));
    $phase->add();
    while ($phase->get() < 4) {
        usleep(1000);
    }
});
$serv->on('Shutdown', function () {
    echo "shutdown\n";
});
$serv->addProcess(new Swoole\Process(function () use ($serv, $port) {
    [, $workerStarts] = Thread::getArguments();

    $wait = function (callable $condition) {
        for ($i = 0; $i < 1000 && !$condition(); $i++) {
            usleep(10 * 1000);
        }
        Assert::true($condition());
    };
    $clients = [];
    $connect = function (int $owner) use ($port, &$clients) {
        for ($i = 0; $i < 20; $i++) {
            $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
            $client->set(['timeout' => 5]);
            Assert::true($client->connect('127.0.0.1', $port, 5));
            $clients[] = $client;
            Assert::greaterThan($client->send("owner\n"), 0);
            [$worker, $fd] = array_map('intval', explode(':', trim($client->recv())));
            if ($worker === $owner) {
                return [$client, $fd];
            }
        }
        throw new RuntimeException("Failed to open a connection on worker {$owner}.");
    };

    $wait(fn () => $workerStarts->get() === 3);
    [$client0, $fd0] = $connect(0);
    [$client1, $fd1] = $connect(1);

    Assert::greaterThan($client0->send("stop:{$fd1}\n"), 0);
    Assert::greaterThan($client1->send("stop:{$fd0}\n"), 0);

    $wait(fn () => $workerStarts->get() === 5);
    echo "restarted\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
restarted
shutdown
