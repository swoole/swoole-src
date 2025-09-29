--TEST--
swoole_process: useQueue
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function(Swoole\Process $proc) {
    echo $proc->pop();
});
$proc->useQueue();
$proc->start();
$proc->push("SUCCESS");

\Swoole\Process::wait(true);
$proc->freeQueue();
?>
--EXPECT--
SUCCESS
