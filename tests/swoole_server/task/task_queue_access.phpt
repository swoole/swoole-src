--TEST--
swoole_server/task: restrict task queue access and accept external packets
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

$key = 0x71000000 + (getmypid() & 0xffff);
$logFile = sys_get_temp_dir() . '/swoole-task-queue-access-' . getmypid() . '.log';
@unlink($logFile);

if (msg_queue_exists($key)) {
    msg_remove_queue(msg_get_queue($key));
}
$queue = msg_get_queue($key, 0666);
msg_set_queue($queue, ['msg_perm.mode' => 0666]);

$small = 'small task';
$large = str_repeat('L', 32 * 1024);
$processed = new Atomic(0);
$mode = null;

$pm = new ProcessManager();
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($key, $small, $large, &$mode) {
    $queue = msg_get_queue($key, 0600);
    $mode = msg_stat_queue($queue)['msg_perm.mode'] & 0777;
    Assert::true(msg_send($queue, 1, Task::pack($small), false));
    Assert::true(msg_send($queue, 1, Task::pack($large), false));
};
$pm->childFunc = function () use ($pm, $key, $logFile, $small, $large, $processed) {
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
    $server->on('Task', function (Server $server, int $taskId, int $workerId, string $data) use (
        $small,
        $large,
        $processed
    ) {
        Assert::true($data === $small || $data === $large);
        if ($processed->add(1) === 2) {
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
Assert::eq($processed->get(), 2);
Assert::true(str_contains($log, 'discarded 0 pending messages'));
?>
--EXPECT--
