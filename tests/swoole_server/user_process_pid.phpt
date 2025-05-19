--TEST--
swoole_server: user process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Process;
use Swoole\Http\Server;
use SwooleTest\ProcessManager;

$atomic = new Atomic;
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $atomic) {
    $url = "http://127.0.0.1:" . $pm->getFreePort() . "/";
    Assert::eq(file_get_contents($url), $atomic->get());
    $pm->wait();
    Assert::eq(file_get_contents($url), $atomic->get());
    usleep(100000);
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $atomic) {
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort(), SWOOLE_PROCESS);
    $process = new Process(function ($process) use ($serv, $pm, $atomic) {
        $atomic->set(posix_getpid());
        usleep(100000);
        $pm->wakeup();
    });
    $serv->set([
        'worker_num' => 2,
        'task_worker_num' => 3,
        'log_file' => '/dev/null',
    ]);
    $serv->on('Request', function ($req, $resp) use ($serv) {
        $resp->end($serv->getWorkerPid(5));
    });
    $serv->on('task', function (){});
    $serv->addProcess($process);
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
