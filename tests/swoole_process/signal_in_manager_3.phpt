--TEST--
swoole_process: signal in manager with task worker - 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Process;
use Swoole\Server;

const PID_FILE = __DIR__ . '/manager.pid';

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    usleep(100000);
    $manager_pid = file_get_contents(PID_FILE);
    Process::kill($manager_pid, SIGINT);
    $pm->wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 2,
        'task_worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on('ManagerStart', function (Server $serv) use ($pm) {
        file_put_contents(PID_FILE, $serv->getManagerPid());
        Process::signal(SIGINT, function () use ($pm) {
            echo "SIGINT triggered\n";
            $pm->wakeup();
        });
        $pm->wakeup();
    });
    $serv->on('workerStop', function ($server) {
        echo "worker exit\n";
    });
    $serv->on('Task', function ($server, $taskId, $workerId, $data) {
    });
    $serv->on('Receive', function (Server $serv, $fd, $reactorId, $data) {
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
unlink(PID_FILE);
?>
--EXPECT--
SIGINT triggered
worker exit
worker exit
worker exit
