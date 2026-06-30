--TEST--
swoole_coroutine_scheduler: add task after empty start
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$scheduler = new Co\Scheduler();

Assert::false($scheduler->start());
$scheduler->add(function () {
    echo "Done\n";
});
Assert::true($scheduler->start());
?>
--EXPECTF--
Warning: Swoole\Coroutine\Scheduler::start(): no coroutine task in %s on line %d
Done
