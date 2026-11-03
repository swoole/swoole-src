--TEST--
swoole_process_pool: SysV messages ignore max_package_size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Process\Pool;

$queueFile = tempnam(sys_get_temp_dir(), 'swoole_pool_');
$queueKey = ftok($queueFile, 'q');
$queue = new Process(static function () {}, false, false);
Assert::true($queue->useQueue($queueKey));
$messages = ['x', random_bytes(1024), random_bytes(1025), '!'];

try {
    $pool = new Pool(1, SWOOLE_IPC_MSGQUEUE, $queueKey);
    $pool->set(['max_package_size' => 1]);
    $pool->on('workerStart', function (Pool $pool) use ($queueKey, $messages) {
        $process = $pool->getProcess();
        Assert::true($process->useQueue($queueKey));
        Assert::true($process->push($messages[0]));
    });
    $received = [];
    $pool->on('message', function (Pool $pool, string $message) use ($messages, &$received) {
        $received[] = $message;
        if ($message === '!') {
            Assert::same($received, $messages);
            $pool->shutdown();
            echo "DONE\n";
        } else {
            // Consume each message before enqueuing the next: macOS queues may hold only 2048 bytes.
            Assert::true($pool->getProcess()->push($messages[count($received)]));
        }
    });
    $pool->start();
} finally {
    $queue->freeQueue();
    unlink($queueFile);
}
?>
--EXPECT--
DONE
