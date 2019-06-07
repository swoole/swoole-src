--TEST--
swoole_process: useQueue
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function(\swoole_process $proc) {
    echo $proc->pop();
});
$proc->useQueue();
$proc->start();
$proc->push("SUCCESS");

\swoole_process::wait(true);
$proc->freeQueue();
?>
--EXPECT--
SUCCESS
