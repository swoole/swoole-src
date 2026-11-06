--TEST--
swoole_server/task: restrict task stream socket access
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;
use SwooleTest\ProcessManager;

$worker = function_exists('posix_geteuid') && posix_geteuid() === 0 ? posix_getpwnam('nobody') : false;
$mode = null;
$owner = null;
$processed = new Swoole\Atomic(0);
$creatorPid = new Swoole\Atomic(0);
$logFile = sys_get_temp_dir() . '/swoole-task-socket-access-' . getmypid() . '.log';
@unlink($logFile);

$pm = new ProcessManager();
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($pm, $processed, $creatorPid, &$mode, &$owner) {
    $socketFile = "/tmp/swoole.task.{$creatorPid->get()}.sock";
    clearstatcache(true, $socketFile);
    $mode = fileperms($socketFile) & 0777;
    $owner = fileowner($socketFile);

    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
    Assert::eq($client->send('task'), 4);
    $client->close();
    Assert::true($processed->wait(5));
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $processed, $creatorPid, $worker, $logFile) {
    umask(0000);
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $settings = [
        'worker_num' => 1,
        'task_worker_num' => 1,
        'task_ipc_mode' => 4,
        'log_file' => $logFile,
    ];
    if ($worker !== false) {
        $settings['user'] = $worker['name'];
    }
    $server->set($settings);
    $server->on('WorkerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
        Assert::integer($server->task($data));
    });
    $server->on('Task', function (Server $server, int $taskId, int $workerId, string $data) use ($processed) {
        Assert::eq($data, 'task');
        $processed->wakeup();
    });
    $creatorPid->set(getmypid());
    $server->start();
};

$pm->childFirst();
$pm->run();
@unlink($logFile);

Assert::eq($mode, 0600);
if ($worker !== false) {
    Assert::eq($owner, $worker['uid']);
}
?>
--EXPECT--
