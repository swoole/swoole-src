--TEST--
swoole_server: enable_reuse_port serves every request without assuming a worker distribution
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

const N = 32;
const W = 4;

$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(10);
$count = new Swoole\Atomic();
$payload = str_repeat('reuse-port-payload', 256) . "\r\n\r\n";
$pm->parentFunc = function () use ($pm, $payload) {
    $scheduler = new Swoole\Coroutine\Scheduler();
    $workerCounter = [];
    $scheduler->parallel(N, function () use ($pm, $payload, &$workerCounter) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $client->set(['open_eof_check' => true, 'package_eof' => "\r\n\r\n"]);
        try {
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
            Assert::same($client->send($payload), strlen($payload));
            $data = $client->recv(5);
            Assert::notEmpty($data);
            $response = json_decode($data, true, 512, JSON_THROW_ON_ERROR);
            Assert::greaterThanEq($response['worker'], 0);
            Assert::lessThan($response['worker'], W);
            Assert::same($response['hash'], md5($payload));
            $workerCounter[$response['worker']] = ($workerCounter[$response['worker']] ?? 0) + 1;
        } finally {
            $client->close();
        }
    });
    try {
        $scheduler->start();
    } finally {
        $pm->kill();
    }
    // Accept scheduling depends on the kernel and load; a fixed per-worker quota is not guaranteed.
    Assert::same(array_sum($workerCounter), N);
};
$pm->childFunc = function () use ($pm, $count, $payload) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'package_eof' => "\r\n\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
        'enable_reuse_port' => true,
        'worker_num' => W,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function (Server $server) use ($pm, $count) {
        // Linux creates a listener per worker; other platforms use the shared listener fallback.
        if (PHP_OS_FAMILY === 'Linux' && defined('SO_REUSEPORT')) {
            Assert::same(socket_get_option($server->getSocket(), SOL_SOCKET, SO_REUSEPORT), 1);
        }
        if ($count->add() === W) {
            $pm->wakeup();
        }
    });
    $server->on('Receive', function (Server $server, $fd, $rid, $data) use ($payload) {
        Assert::same($data, $payload);
        $server->send($fd, json_encode(['worker' => $server->getWorkerId(), 'hash' => md5($data)]) . "\r\n\r\n");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
Assert::same($count->get(), W);
?>
--EXPECT--
