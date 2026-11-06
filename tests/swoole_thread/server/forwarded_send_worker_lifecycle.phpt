--TEST--
swoole_thread/server: forwarded sends during event worker replacement
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
use Swoole\Http\Server;
use Swoole\Thread;

$port = get_constant_port(__FILE__);

$serv = new Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set([
    'worker_num'       => 2,
    'enable_coroutine' => false,
    'log_file'         => '/dev/null',
    'log_level'        => SWOOLE_LOG_ERROR,
    'init_arguments'   => function () {
        global $ready, $connection, $starts, $state;
        $ready      = new Thread\Queue();
        $connection = new Thread\Queue();
        $starts     = new Thread\Atomic(0);
        $state      = new Thread\Map();
        return [$ready, $connection, $starts, $state];
    },
]);
$serv->on('WorkerStart', function (Server $serv, int $workerId) {
    [$ready, $connection, $starts, $state] = Thread::getArguments();
    $generation                            = $starts->add();
    if ($generation === 2) {
        $ready->push('ready', Thread\Queue::NOTIFY_ALL);
    }
    register_shutdown_function(function () use ($serv, $starts, $state, $workerId) {
        if ($starts->get() === 2 && $workerId !== $state['owner']) {
            Assert::true($serv->send($state['fd'], "worker-shutdown\n"));
        }
    });
    if ($generation === 3) {
        Assert::true($serv->send($state['fd'], "worker-start\n"));
    }
});
$serv->on('Request', function ($request, $response) use ($serv) {
    [$ready, $connection, $starts, $state] = Thread::getArguments();
    $response->detach();
    $state['fd']    = $request->fd;
    $state['owner'] = $serv->worker_id;
    $connection->push('ready', Thread\Queue::NOTIFY_ALL);
});
$serv->on('Shutdown', function () {
    echo "shutdown\n";
});
$serv->addProcess(new Swoole\Process(function () use ($serv, $port) {
    [$ready, $connection, $starts, $state] = Thread::getArguments();
    $ready->pop(-1);

    Coroutine\run(function () use ($serv, $port, $connection, $state) {
        $client = new Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $port));
        Assert::greaterThan($client->send("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), 0);
        $connection->pop(-1);

        Assert::true($serv->stop(1 - $state['owner']));
        $data = '';
        while (substr_count($data, "\n") < 2) {
            $chunk = $client->recv();
            Assert::notEmpty($chunk);
            $data .= $chunk;
        }
        echo $data;
        $client->close();
        $serv->shutdown();
    });
}));
$serv->start();
?>
--EXPECT--
worker-shutdown
worker-start
shutdown
