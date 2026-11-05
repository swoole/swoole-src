--TEST--
swoole_thread/server: forward a chunked send from the initial WorkerStart
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;
use Swoole\Http\Server;
use Swoole\Thread;

Assert::setThrowException(true);

// Exceed the MessageBus buffer size so forwarding also exercises IPC chunking.
const PAYLOAD_SIZE = 128 * 1024;

$port = get_constant_port(__FILE__);
$server = new Server('127.0.0.1', $port, SWOOLE_THREAD);
$server->set([
    'worker_num' => 2,
    'enable_coroutine' => false,
    'log_file' => '/dev/null',
    'log_level' => SWOOLE_LOG_ERROR,
    'init_arguments' => function () {
        global $ready, $connections;
        $ready = new Thread\Queue();
        $connections = new Thread\Queue();
        return [$ready, $connections];
    },
]);
$server->on('WorkerStart', function (Server $server, int $workerId) {
    [$ready, $connections] = Thread::getArguments();
    if ($workerId === 0) {
        $ready->push('worker-ready', Thread\Queue::NOTIFY_ALL);
        return;
    }

    // Keep worker 1 inside its first WorkerStart until worker 0 owns a connection.
    // Sending to that connection must use worker 1's fully initialized MessageBus.
    $target = $connections->pop(-1);
    Assert::true($server->send($target['fd'], str_repeat('x', PAYLOAD_SIZE)));
    $ready->push($target['port'], Thread\Queue::NOTIFY_ALL);
});
$server->on('Request', function ($request, $response) {
    [, $connections] = Thread::getArguments();
    $response->detach();
    $connections->push([
        'fd' => $request->fd,
        'port' => $request->server['remote_port'],
    ], Thread\Queue::NOTIFY_ALL);
});
$server->on('Shutdown', function () {
    echo "shutdown\n";
});
$server->addProcess(new Swoole\Process(function () use ($server, $port) {
    [$ready] = Thread::getArguments();
    Assert::same($ready->pop(-1), 'worker-ready');

    Coroutine\run(function () use ($server, $port, $ready) {
        $clients = [];
        // Allocate client descriptors before connecting. Otherwise interleaved client/server
        // allocations can give all accepted descriptors the same parity and select worker 1.
        for ($i = 0; $i < 4; $i++) {
            $clients[] = new Socket(AF_INET, SOCK_STREAM, 0);
        }
        foreach ($clients as $client) {
            Assert::true($client->connect('127.0.0.1', $port, 5));
            $request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
            Assert::same($client->sendAll($request), strlen($request));
        }

        $targetPort = $ready->pop(-1);
        $received = false;
        foreach ($clients as $client) {
            if ($client->getsockname()['port'] === $targetPort) {
                Assert::same($client->recvAll(PAYLOAD_SIZE, 5), str_repeat('x', PAYLOAD_SIZE));
                $received = true;
            }
            $client->close();
        }
        Assert::true($received);
        echo "initial-forward-ok\n";
        $server->shutdown();
    });
}));
$server->start();
?>
--EXPECT--
initial-forward-ok
shutdown
