--TEST--
swoole_process: pop
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

// TODO 难道 queue不应该做成一个独立的组件，放在proc对象上啥意思
$proc = new \swoole_process(function() { });
$proc->useQueue();
$proc->push("SUCCESS");
echo $proc->pop();
$proc->freeQueue();
?>
--EXPECT--
SUCCESS
