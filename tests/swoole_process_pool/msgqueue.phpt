--TEST--
swoole_process_pool: sysv msgqueue
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
if (function_exists('msg_get_queue') == false) {
    die("SKIP, no sysvmsg extension.");
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;

const N = 100;
const MSGQ_KEY = 0x70000001;

$pm = new ProcessManager;
$atomic = new Atomic();

$pm->parentFunc = function ($pid) use ($pm, $atomic) {
    $seg = msg_get_queue(MSGQ_KEY);
    foreach (range(1, N) as $i) {
        $data = json_encode(['data' => base64_encode(random_bytes(1024)), 'id' => uniqid(), 'index' => $i,]);
        msg_send($seg, $i, $data, false);
    }
};

$pm->childFunc = function () use ($pm, $atomic) {
    $pool = new Swoole\Process\Pool(1, SWOOLE_IPC_MSGQUEUE, MSGQ_KEY);

    $pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) use ($pm) {
        echo "worker start\n";
        $pm->wakeup();
    });

    $pool->on("message", function (Swoole\Process\Pool $pool, string $message) use ($atomic) {
        $data = json_decode($message, true);
        Assert::assert($data);
        Assert::assert(is_array($data));
        Assert::same(strlen(base64_decode($data['data'])), 1024);
        $atomic->add(1);
        if ($atomic->get() == 100) {
            $pool->shutdown();
            echo "DONE\n";
        }
    });

    $pool->on('workerStop', function (Swoole\Process\Pool $pool, int $workerId) {
        echo "worker stop\n";
    });

    $pool->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
worker start
DONE
worker stop
