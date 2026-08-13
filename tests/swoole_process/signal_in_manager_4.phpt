--TEST--
swoole_process: register and unregister signal in manager
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
    // The manager process must still be alive here. Registering or unregistering a signal
    // handler in onManagerStart used to segfault the manager process, because
    // swoole_event_defer() dereferenced the null reactor.
    Assert::true(Process::kill($manager_pid, 0));
    // The removed callback must not be invoked (SIGINT is ignored after unregistration).
    Process::kill($manager_pid, SIGINT);
    usleep(100000);
    Assert::true(Process::kill($manager_pid, 0));
    Process::kill($manager_pid, SIGTERM);
    $pm->wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on('ManagerStart', function (Server $serv) use ($pm) {
        file_put_contents(PID_FILE, $serv->getManagerPid());
        Process::signal(SIGINT, static function () {
            echo "SIGINT triggered\n";
        });
        Assert::true(Process::signal(SIGINT, null));
        echo "signal unregistered\n";
        $pm->wakeup();
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
signal unregistered
