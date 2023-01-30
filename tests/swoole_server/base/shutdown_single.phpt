--TEST--
swoole_server/base: shutdown [single process]
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $client = new Co\Client(SWOOLE_SOCK_TCP);
        Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
        Assert::assert($client->send($pm->getRandomData()) > 0);
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('start', function (Server $server) use ($pm) {
        echo "START\n";
        Assert::eq($server->getManagerPid(), 0);
        Assert::eq($server->getMasterPid(), posix_getpid());
        $pm->wakeup();
    });
    $server->on('receive', function (Server $server, int $fd, int $rid, string $data) use ($pm) {
        Assert::same($data, $pm->getRandomData());
        $server->shutdown();
    });
    $server->on('shutdown', function () {
        echo "SHUTDOWN\n";
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
$pm->expectExitCode(0);
?>
--EXPECT--
START
SHUTDOWN
