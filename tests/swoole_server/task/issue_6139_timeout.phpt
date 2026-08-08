--TEST--
swoole_server/task: replay deferred client data after graceful shutdown timeout
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Client;
use Swoole\Process;
use Swoole\Server;
use SwooleTest\ProcessManager;

$workerPid = new Atomic();
$taskStarted = new Atomic();
$workerExiting = new Atomic();
$pm = new ProcessManager();
$pm->setWaitTimeout(8);
$pm->parentFunc = function (int $pid) use ($pm, $workerPid, $taskStarted, $workerExiting) {
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'open_eof_check' => true,
        'package_eof' => "\r\n\r\n",
    ]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    Assert::same($client->send("task\r\n\r\n"), 8);
    Assert::true($taskStarted->wait(2));

    Assert::true(Process::kill($workerPid->get(), SIGTERM));
    for ($i = 0; $i < 200 && $workerExiting->get() === 0; $i++) {
        usleep(10000);
    }
    Assert::same($workerExiting->get(), 1);
    Assert::same($client->send("data\r\n\r\n"), 8);
    Assert::same(trim($client->recv()), 'DATA');
    echo "SUCCESS\n";

    $pm->kill();
};
$pm->childFunc = function () use ($pm, $workerPid, $taskStarted, $workerExiting) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'task_worker_num' => 1,
        'enable_coroutine' => false,
        'reload_async' => true,
        'max_wait_time' => 1,
        'log_file' => '/dev/null',
        'open_eof_check' => true,
        'package_eof' => "\r\n\r\n",
    ]);
    $server->on('WorkerStart', function (Server $server, int $workerId) use ($pm, $workerPid) {
        if ($workerId === 0 && $workerPid->cmpset(0, getmypid())) {
            $pm->wakeup();
        }
    });
    $server->on('WorkerExit', function () use ($workerExiting) {
        $workerExiting->set(1);
        $workerExiting->wakeup();
    });
    $server->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) use ($workerPid) {
        if (trim($data) === 'task') {
            Assert::integer($server->task('slow'));
        } else {
            Assert::notSame(getmypid(), $workerPid->get());
            Assert::integer($server->task('late', -1, function (Server $server) use ($fd) {
                Assert::true($server->send($fd, "DATA\r\n\r\n"));
            }));
        }
    });
    $server->on('Task', function (Server $server, int $taskId, int $sourceWorkerId, string $data) use ($taskStarted) {
        if ($data === 'slow') {
            $taskStarted->wakeup();
            sleep(3);
            return null;
        }
        return $data;
    });
    $server->on('Finish', function () {});
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
