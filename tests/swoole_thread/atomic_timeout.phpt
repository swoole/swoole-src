--TEST--
Swoole\Thread\Atomic: threads with different wait timeouts
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Atomic;

const N = 9;
$args = Thread::getArguments();

if (empty($args)) {
    $threads = [];
    $atomic = new Atomic(1);
    $ready = new Atomic(0);
    Assert::true($atomic->wait());

    for ($i = 0; $i < N; $i++) {
        $threads[] = new Thread(__FILE__, $atomic, $ready, $i);
    }

    while ($ready->get() !== N) {
        usleep(1000);
    }
    sleep(1);
    echo "main thread lock success\n";
    $atomic->wakeup(N);

    foreach ($threads as $thread) {
        $thread->join();
    }
} else {
    [$atomic, $ready, $i] = $args;
    $ready->add();
    while ($ready->get() !== N) {
        usleep(1000);
    }

    $timeout = ($i === 5 || $i === 6) ? 0.8 : 0;

    if ($atomic->wait($timeout)) {
        sleep(1);
        echo "thread $i lock success\n";
    } elseif ($i === 5 || $i === 6) {
        echo "thread $i timeout\n";
    } else {
        echo "thread $i lock failed\n";
    }
}
?>
--EXPECTF--
thread %d timeout
thread %d timeout
main thread lock success
thread %d lock failed
thread %d lock failed
thread %d lock failed
thread %d lock failed
thread %d lock failed
thread %d lock failed
thread %d lock success
