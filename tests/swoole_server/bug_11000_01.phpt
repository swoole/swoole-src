--TEST--
swoole_server: bug_11000_01
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->childFunc = function () {
    $port = get_one_free_port();
    $serv = new Server(TCP_SERVER_HOST, $port);
    $process = new \Swoole\Process(function ($process) use ($serv) {
        usleep(10000);
        $stats = $serv->stats();
        Assert::isArray($stats);
        Assert::keyExists($stats, 'connection_num');
        Assert::keyExists($stats, 'request_count');
        $serv->shutdown();
    });
    $serv->set(['worker_num' => 2, 'log_file' => '/dev/null']);
    $serv->on('receive', function () { });
    $serv->addProcess($process);
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
