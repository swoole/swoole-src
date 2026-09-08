--TEST--
swoole_server/task: replace writable task queue backlog
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_function_not_exist('msg_get_queue');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Server;
use Swoole\Server\Task;
use SwooleTest\ProcessManager;

$key = 0x72000000 + (getmypid() & 0xffff);
$logFile = sys_get_temp_dir() . '/swoole-task-queue-replace-' . getmypid() . '.log';
@unlink($logFile);

if (msg_queue_exists($key)) {
    msg_remove_queue(msg_get_queue($key));
}
$queue = msg_get_queue($key, 0666);
msg_set_queue($queue, ['msg_perm.mode' => 0666]);
Assert::true(msg_send($queue, 1, Task::pack('stale'), false));

$stale = new Atomic(0);
$fresh = new Atomic(0);
$mode = null;

$pm = new ProcessManager();
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($key, &$mode) {
    $queue = msg_get_queue($key, 0600);
    $mode = msg_stat_queue($queue)['msg_perm.mode'] & 0777;
    Assert::true(msg_send($queue, 1, Task::pack('fresh'), false));
};
$pm->childFunc = function () use ($pm, $key, $logFile, $stale, $fresh) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'task_worker_num' => 1,
        'task_ipc_mode' => 3,
        'message_queue_key' => $key,
        'log_file' => $logFile,
    ]);
    $server->on('WorkerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('Receive', function () {});
    $server->on('Task', function (Server $server, int $taskId, int $workerId, string $data) use ($stale, $fresh) {
        if ($data === 'stale') {
            $stale->add(1);
        } elseif ($data === 'fresh') {
            $fresh->add(1);
            $server->shutdown();
        }
    });
    $server->start();
};

$pm->childFirst();
$pm->run();

$queue = msg_get_queue($key, 0600);
msg_remove_queue($queue);
$log = @file_get_contents($logFile) ?: '';
@unlink($logFile);

Assert::eq($mode, 0600);
Assert::eq($stale->get(), 0);
Assert::eq($fresh->get(), 1);
Assert::true(str_contains($log, 'discarded 1 pending message'));
?>
--EXPECT--
