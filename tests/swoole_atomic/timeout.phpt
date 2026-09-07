--TEST--
Swoole\Atomic: processes with different wait timeouts
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist('Swoole\Atomic');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Process;

const N = 9;
$atomic = new Atomic(1);
$ready = new Atomic(0);
Assert::true($atomic->wait());

for ($i = 0; $i < N; $i++) {
    $process = new Process(function () use ($atomic, $ready, $i) {
        $ready->add();
        while ($ready->get() !== N) {
            usleep(1000);
        }

        $timeout = ($i === 5 || $i === 6) ? 0.8 : 0;
        if ($atomic->wait($timeout)) {
            sleep(1);
            echo "process $i lock success\n";
        } elseif ($i === 5 || $i === 6) {
            echo "process $i timeout\n";
        } else {
            echo "process $i lock failed\n";
        }
    });
    $process->start();
}

while ($ready->get() !== N) {
    usleep(1000);
}
sleep(1);
echo "parent lock success\n";
$atomic->wakeup(N);

for ($i = 0; $i < N; $i++) {
    Process::wait();
}
?>
--EXPECTF--
process %d timeout
process %d timeout
parent lock success
process %d lock failed
process %d lock failed
process %d lock failed
process %d lock failed
process %d lock failed
process %d lock failed
process %d lock success
