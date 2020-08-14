--TEST--
swoole_timer: memory leak test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$stat = new stdClass();
$stat->count = 0;
$stat->m0 = memory_get_usage();
$stat->data = [];

Swoole\Timer::tick(1, function ( $id ) use ( &$stat ) {
    $obj = new stdClass();
    $obj->name = random_bytes(8192);
    $stat->data = $obj->name;
    $stat->count++;
    if ($stat->count == 1) {
        $stat->m1 = memory_get_usage();
        echo 'diff[0] ' . ($stat->m1 - $stat->m0) . "\n";
    } elseif ($stat->count == 99) {
        $stat->m2 = memory_get_usage();
        Assert::lessThan($stat->m2 - $stat->m1, 128);
        echo 'diff[1] ' . ($stat->m2 - $stat->m1) . "\n";
        swoole_timer_clear($id);
    }
});

\Swoole\Event::wait();
$stat->m3 = memory_get_usage();
$stat->data = null;
echo 'diff[2] ' . ($stat->m3 - $stat->m0) . "\n";

?>
--EXPECTF--
diff[0] %d
diff[1] %d
diff[2] %d
