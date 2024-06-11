--TEST--
swoole_thread: async-io
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

const C = 4;
const N = 256;
const M = 9999;

$args = Thread::getArguments();
$running = true;
$md5 = md5_file(__FILE__);

if (empty($args)) {
    $threads = [];
    $atomic = new Swoole\Thread\Atomic();
    $atomicLong = new Swoole\Thread\Atomic\Long();
    for ($i = 0; $i < C; $i++) {
        $threads[] = new Thread(__FILE__, $i, $atomic, $atomicLong);
    }
    for ($i = 0; $i < C; $i++) {
        $threads[$i]->join();
    }
    Assert::eq($atomic->get(), C * N);
    Assert::eq($atomicLong->get(), C * N * M);
} else {
    $id = $args[0];
    $atomic = $args[1];
    $atomicLong = $args[2];
    Co\run(function () use ($atomic, $atomicLong, $md5) {
        $n = N;
        while ($n--) {
            $atomic->add();
            $atomicLong->add(M);
            $rs = \Swoole\Coroutine\System::readFile(__FILE__);
            Assert::eq(md5($rs), $md5);
        }
    });
    exit(0);
}
echo "DONE\n";
?>
--EXPECTF--
DONE
