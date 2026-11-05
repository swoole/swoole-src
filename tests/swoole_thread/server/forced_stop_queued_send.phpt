--TEST--
swoole_thread/server: forced worker stop delivers queued cross-thread sends, or discards them at shutdown
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Timer;

const QUEUED_BYTES = 4 * 1024 * 1024;

$port = get_constant_port(__FILE__);
$path = sys_get_temp_dir() . '/swoole_thread_forced_stop_' . $port . '.bin';

$serv = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set([
    'worker_num'       => 3,
    'reload_async'     => false,
    // a blocked worker must not yield to its event loop
    'enable_coroutine' => false,
    'log_level'        => SWOOLE_LOG_ERROR,
    'log_file'         => '/dev/null',
    'open_eof_check'   => true,
    'package_eof'      => "\n",
    'init_arguments'   => function () use ($path) {
        global $ready, $state, $target;
        file_put_contents($path, 'delete me');
        $ready = new Thread\Atomic(0);
        $state = new Thread\Atomic(0);
        $target = new Thread\Atomic(0);
        return [$ready, $state, $target];
    },
]);
$serv->on('WorkerStart', function () {
    [$ready] = Thread::getArguments();
    $ready->add();
});
$serv->on('Receive', function (Swoole\Server $serv, int $fd, int $reactorId, string $data) use ($path) {
    [, $state, $target] = Thread::getArguments();

    switch (trim($data)) {
        case 'owner':
            $serv->send($fd, $serv->getClientInfo($fd)['reactor_id'] . "\n");
            break;

        // The target connection's worker stops reading its pipe, so the other worker's sends stay queued.
        case 'block_restart':
            $target->set($fd);
            $state->set(1);
            while ($state->get() < 2) {
                usleep(1000);
            }
            // let the stopped worker's event loop end before its queued data can be read
            usleep(200 * 1000);
            break;

        case 'block_shutdown':
            $target->set($fd);
            $state->set(3);
            for ($i = 0; $i < 200 && is_file($path); $i++) {
                usleep(10 * 1000);
                clearstatcache();
            }
            echo is_file($path) ? "file remains\n" : "file deleted\n";
            break;

        case 'queue_stop':
            Assert::true($serv->send($target->get(), str_repeat('x', QUEUED_BYTES)));
            Assert::true($serv->stop());
            $state->set(2);
            break;

        case 'queue_shutdown':
            Assert::true($serv->send($target->get(), str_repeat('x', QUEUED_BYTES)));
            Assert::true($serv->sendfile($target->get(), $path, 0, 0, true));
            $state->set(4);
            break;
    }
});
$serv->on('Start', function (Swoole\Server $serv) {
    // shut down from the master thread once the owned file is queued
    Timer::tick(10, function (int $timerId) use ($serv) {
        global $state;
        if ($state->get() === 4) {
            Timer::clear($timerId);
            $serv->shutdown();
        }
    });
});
$serv->on('BeforeShutdown', function () {
    global $state;
    echo "before shutdown\n";
    $state->set(5);
});
// a stopped worker thread also returns from start(), so clean up only at shutdown
$serv->on('Shutdown', function () use ($path) {
    @unlink($path);
    echo "shutdown\n";
});
$serv->addProcess(new Swoole\Process(function () use ($serv, $port) {
    [$ready, $state] = Thread::getArguments();

    $wait = function (callable $condition) {
        for ($i = 0; $i < 1000 && !$condition(); $i++) {
            usleep(10 * 1000);
        }
        Assert::true($condition());
    };
    // keep every client open, so a new connection does not reuse the fd of one on the wrong worker
    $clients = [];
    $connect = function (int $owner) use ($port, &$clients) {
        for ($i = 0; $i < 20; $i++) {
            $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
            $client->set(['timeout' => 5]);
            Assert::true($client->connect('127.0.0.1', $port, 5));
            $clients[] = $client;
            Assert::greaterThan($client->send("owner\n"), 0);
            if ((int) trim($client->recv()) === $owner) {
                return $client;
            }
        }
        throw new RuntimeException("Failed to open a connection on worker {$owner}.");
    };

    $wait(fn () => $ready->get() === 3);
    $target = $connect(1);

    // worker 0 queues data for worker 1's connection, then stops itself
    $sender = $connect(0);
    Assert::greaterThan($target->send("block_restart\n"), 0);
    $wait(fn () => $state->get() === 1);
    Assert::greaterThan($sender->send("queue_stop\n"), 0);
    $received = 0;
    while ($received < QUEUED_BYTES && ($data = $target->recv(65536))) {
        $received += strlen($data);
    }
    echo $received === QUEUED_BYTES ? "delivered\n" : "received {$received} of " . QUEUED_BYTES . "\n";

    // the restarted worker 0 queues data and an owned file for worker 1's connection, then the master shuts down
    $wait(fn () => $ready->get() === 4);
    $sender = $connect(0);
    Assert::greaterThan($target->send("block_shutdown\n"), 0);
    $wait(fn () => $state->get() === 3);
    Assert::greaterThan($sender->send("queue_shutdown\n"), 0);
    $wait(fn () => $state->get() === 5);
}));
$serv->start();
?>
--EXPECT--
delivered
before shutdown
file deleted
shutdown
