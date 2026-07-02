--TEST--
swoole_coroutine_scheduler: negative dns_cache_capacity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$scheduler = new Swoole\Coroutine\Scheduler();
$scheduler->set(['dns_cache_capacity' => -1]);
$scheduler->add(function () {
    Assert::eq(Swoole\Coroutine::gethostbyname('localhost'), '127.0.0.1');
});
$scheduler->start();

echo "DONE\n";
?>
--EXPECT--
DONE
