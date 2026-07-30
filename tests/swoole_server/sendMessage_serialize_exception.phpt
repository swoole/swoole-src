--TEST--
swoole_server: sendMessage serialization exception
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();

$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'package_eof'    => "\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
    ]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 10));
    echo $client->recv();
    echo $client->recv();
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $server->set([
        'log_file'   => '/dev/null',
        'worker_num' => 2,
    ]);
    $server->on('workerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('connect', function (Server $server, int $fd) {
        try {
            $server->sendMessage([1, $server], 1 - $server->getWorkerId());
        } catch (Throwable $exception) {
            Assert::contains($exception->getMessage(), 'Serialization');
            Assert::true($server->send($fd, "CAUGHT\r\n"));
        }

        Assert::true($server->sendMessage(['fd' => $fd], 1 - $server->getWorkerId()));
    });
    $server->on('receive', function () {});
    $server->on('pipeMessage', function (Server $server, int $workerId, array $message) {
        Assert::true($server->send($message['fd'], "OK\r\n"));
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
CAUGHT
OK
