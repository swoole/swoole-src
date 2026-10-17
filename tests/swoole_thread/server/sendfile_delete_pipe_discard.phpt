--TEST--
swoole_thread/server: discarded cross-thread sendfile deletes its owned file
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

const QUEUED_BYTES = 17 * 1024 * 1024;
const SEND_CHUNK_BYTES = 64 * 1024;

$port = get_constant_port(__FILE__);
$path = sys_get_temp_dir() . '/swoole_thread_sendfile_pipe_discard_' . $port . '.bin';

$serv = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set([
    'worker_num'              => 3,
    'log_level'               => SWOOLE_LOG_ERROR,
    'log_file'                => '/dev/null',
    'open_eof_check'          => true,
    'package_eof'             => "\n",
    'discard_timeout_request' => true,
    'init_arguments'          => function () use ($path) {
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
    [$ready, $state, $target] = Thread::getArguments();

    switch (trim($data)) {
        case 'owner':
            $serv->send($fd, $serv->getClientInfo($fd)['reactor_id'] . "\n");
            break;

        case 'block':
            $target->set($fd);
            $state->set(1);
            while ($state->get() < 2) {
                usleep(1000);
            }
            Assert::true($serv->close($fd));
            $state->set(3);
            break;

        case 'queue':
            while ($state->get() < 1) {
                usleep(1000);
            }
            $targetFd = $target->get();
            $chunk = str_repeat('x', SEND_CHUNK_BYTES);
            for ($sent = 0; $sent < QUEUED_BYTES; $sent += SEND_CHUNK_BYTES) {
                Assert::true($serv->send($targetFd, $chunk));
            }
            Assert::true($serv->sendfile($targetFd, $path, 0, 0, true));
            $state->set(2);
            break;
    }
});
$serv->on('Shutdown', function () {
    echo "shutdown\n";
});
$serv->addProcess(new Swoole\Process(function () use ($serv, $path, $port) {
    [$ready, $state] = Thread::getArguments();

    for ($i = 0; $i < 1000 && $ready->get() < 3; $i++) {
        usleep(10 * 1000);
    }
    Assert::same($ready->get(), 3);

    $clients = [];
    $allClients = [];
    for ($i = 0; $i < 10 && count($clients) < 2; $i++) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
        $client->set(['timeout' => 5]);
        Assert::true($client->connect('127.0.0.1', $port, 5));
        $allClients[] = $client;
        Assert::greaterThan($client->send("owner\n"), 0);
        $owner = (int) trim($client->recv());
        if (!isset($clients[$owner])) {
            $clients[$owner] = $client;
        }
    }
    if (count($clients) !== 2) {
        throw new RuntimeException('Failed to open connections on different workers.');
    }
    $clients = array_values($clients);

    Assert::greaterThan($clients[1]->send("block\n"), 0);
    for ($i = 0; $i < 1000 && $state->get() < 1; $i++) {
        usleep(10 * 1000);
    }
    Assert::same($state->get(), 1);

    Assert::greaterThan($clients[0]->send("queue\n"), 0);
    for ($i = 0; $i < 1000 && $state->get() < 3; $i++) {
        usleep(10 * 1000);
    }
    Assert::same($state->get(), 3);

    for ($i = 0; $i < 500; $i++) {
        clearstatcache(true, $path);
        if (!is_file($path)) {
            break;
        }
        usleep(10 * 1000);
    }
    clearstatcache(true, $path);
    $deleted = !is_file($path);

    foreach ($allClients as $client) {
        $client->close();
    }
    echo $deleted ? "done\n" : "file remains\n";
    $serv->shutdown();
}));
$serv->start();
@unlink($path);
?>
--EXPECT--
done
shutdown
