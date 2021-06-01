--TEST--
swoole_process_pool: detach
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process\Pool;
use Swoole\Atomic;

const N = 100;

$atomic = new Atomic();

$pm = new ProcessManager;
$pm->initFreePorts();

$pm->parentFunc = function ($pid) use ($pm, $atomic) {
    foreach (range(1, 2) as $i) {
        $fp = stream_socket_client("tcp://127.0.0.1:".$pm->getFreePort(), $errno, $errstr) or die("error: $errstr\n");
        $msg =  "HELLO-{$i}";
        fwrite($fp, pack('N', strlen($msg)) . $msg);
    }
    $pm->wait();
    Assert::eq($atomic->get(), N + 1);
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $atomic) {
    $pool = new Pool(1, SWOOLE_IPC_SOCKET);

    $pool->on('WorkerStart', function (Pool $pool, $workerId) use($pm, $atomic) {
        echo("[Worker #{$workerId}] WorkerStart\n");
         if ($atomic->get() == 0) {
             $pm->wakeup();
         }
    });

    $pool->on('Message', function (Pool $pool, $msg) use($pm, $atomic) {
        if ($atomic->get() == 0) {
            $atomic->add();
            $pool->detach();
            $n = N;
            while($n--) {
                usleep(1000);
                $atomic->add();
            }
            $pm->wakeup();
        } else {
            echo $msg.PHP_EOL;
        }
    });

    $pool->listen('127.0.0.1', $pm->getFreePort());
    $pool->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
[Worker #0] WorkerStart
[Worker #0] WorkerStart
HELLO-2
DONE
