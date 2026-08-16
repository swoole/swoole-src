--TEST--
Swoole\Atomic: Processes with different timeouts
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Process;

const N = 10;
$atomic = new Atomic(1);

for ($i = 0; $i < N; $i++) {
    $process = new Process(function() use ($atomic, $i) {
        $timeout = ($i == 5 || $i == 6) ? 0.8 : 0;
        $result = $atomic->wait($timeout);
        if ($result) {
            sleep(1);
            echo "process $i lock success" . PHP_EOL;
            $atomic->wakeup(9);
        } else {
            if ($i == 5 || $i == 6) {
                echo "process $i timeout" . PHP_EOL;
            } else {
                echo "process $i lock failed" . PHP_EOL;
            }
        }
    });

    $process->start();
}

for ($i = 0; $i < N; $i++) {
    Swoole\Process::wait();
}

?>
--EXPECTF--
process %d timeout
process %d timeout
process %d lock success
process %d lock failed
process %d lock failed
process %d lock failed
process %d lock failed
process %d lock failed
process %d lock failed
process %d lock success
