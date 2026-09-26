--TEST--
swoole_thread/server: bailout during a forwarded send
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

const PAYLOAD_SIZE = 4 * 1024 * 1024;

$port = get_constant_port(__FILE__);

$serv = new Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set([
    'worker_num' => 1,
    'enable_coroutine' => false,
    'log_file' => '/dev/null',
    'log_level' => SWOOLE_LOG_ERROR,
    'init_arguments' => function () {
        global $ready, $connection, $starts;
        $ready = new Thread\Queue();
        $connection = new Thread\Queue();
        $starts = new Thread\Atomic(0);
        return [$ready, $connection, $starts];
    },
]);
$serv->on('WorkerStart', function () {
    [$ready, $connection, $starts] = Thread::getArguments();
    if ($starts->add() === 1) {
        $ready->push('ready', Thread\Queue::NOTIFY_ALL);
    }
});
$serv->on('Request', function ($request, $response) {
    [$ready, $connection] = Thread::getArguments();
    if ($request->server['request_uri'] === '/block') {
        $connection->push($request->fd, Thread\Queue::NOTIFY_ALL);
        usleep(200_000);
    } else {
        swoole_implicit_fn('bailout');
    }
});
$serv->on('Shutdown', function () {
    echo "shutdown\n";
});
$serv->addProcess(new Swoole\Process(function () use ($serv, $port) {
    [$ready, $connection, $starts] = Thread::getArguments();
    $ready->pop(-1);

    Coroutine\run(function () use ($serv, $port, $connection, $starts) {
        $blocked = new Client(SWOOLE_SOCK_TCP);
        Assert::true($blocked->connect('127.0.0.1', $port));
        Assert::greaterThan($blocked->send("GET /block HTTP/1.1\r\nHost: localhost\r\n\r\n"), 0);

        $fd = $connection->pop(-1);
        Assert::true($serv->send($fd, str_repeat('x', PAYLOAD_SIZE)));

        $bailout = new Client(SWOOLE_SOCK_TCP);
        Assert::true($bailout->connect('127.0.0.1', $port));
        Assert::greaterThan($bailout->send("GET /bailout HTTP/1.1\r\nHost: localhost\r\n\r\n"), 0);

        while ($starts->get() < 2) {
            Coroutine::sleep(0.01);
        }
        $blocked->close();
        $bailout->close();
        echo "restarted\n";
        $serv->shutdown();
    });
}));
$serv->start();
?>
--EXPECT--
restarted
shutdown
