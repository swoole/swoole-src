--TEST--
swoole_thread: co user yield
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Timer;

const C = 4;
const N = 32;

$args = Thread::getArguments();
$running = true;

swoole_async_set(['enable_coroutine' => false]);

if (empty($args)) {
    $threads = [];
    $atomic = new Swoole\Thread\Atomic();
    for ($i = 0; $i < C; $i++) {
        $threads[] = new Thread(__FILE__, $i, $atomic);
    }
    for ($i = 0; $i < C; $i++) {
        $threads[$i]->join();
    }
    Assert::eq($atomic->get(), C * N);
} else {
    $id = $args[0];
    $atomic = $args[1];
    Co\run(function () use ($atomic) {
        $n = N;
        $cid = Co::getCid();
        while ($n--) {
            Timer::after(10, function () use ($cid) {
                Co::resume($cid);
            });
            Co::yield();
            $atomic->add();
        }
    });
    exit(0);
}
echo "DONE\n";
?>
--EXPECT--
DONE
