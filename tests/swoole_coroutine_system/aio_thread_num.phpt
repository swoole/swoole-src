--TEST--
swoole_coroutine_system: gethostbyname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$sch = new Swoole\Coroutine\Scheduler();
$sch->parallel(16, function () {
    $ip = Co::gethostbyname('www.baidu.com');
    Assert::assert($ip != false);
});
$sch->add(function () {
    Assert::greaterThan(Co::stats()['aio_thread_num'], 8);
});
$sch->start();

?>
--EXPECT--
