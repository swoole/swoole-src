--TEST--
Swoole\Thread\Atomic: Threads with different timeouts
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

const N = 10;

$args = Thread::getArguments();
if (empty($args)) {
    $threads = [];
    $atomic = new Atomic(1);

    for ($i = 0; $i < N; $i++) {
        $threads[] = new Thread(__FILE__, $atomic, $i);
    }

    foreach ($threads as $thread) {
        $thread->join();
    }
} else {
    $atomic = $args[0];
    $i = $args[1];

    $timeout = ($i == 5 || $i == 6) ? 0.8 : 0;
    $result = $atomic->wait($timeout);
    if ($result) {
        sleep(1);
        echo "thread $i lock success" . PHP_EOL;
        $atomic->wakeup(9);
    } else {
        if ($i == 5 || $i == 6) {
            echo "thread $i timeout" . PHP_EOL;
        } else {
            echo "thread $i lock failed" . PHP_EOL;
        }
    }
}

?>
--EXPECTF--
thread %d timeout
thread %d timeout
thread %d lock success
thread %d lock failed
thread %d lock failed
thread %d lock failed
thread %d lock failed
thread %d lock failed
thread %d lock failed
thread %d lock success
