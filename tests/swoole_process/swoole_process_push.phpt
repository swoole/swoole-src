--TEST--
swoole_process: push
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

//$proc = new \swoole_process(swoole_function() {});
//$proc->useQueue();
//$r = $proc->push("\0");
// Assert::false($r);
// TODO max data ?
// $r = $proc->push(str_repeat("\0", 1024 * 1024 * 8));
// Assert::false($r);
//$proc->freeQueue();

$proc = new \swoole_process(function() {});
$proc->useQueue();
$proc->start();
$r = $proc->push("\0");
Assert::true($r);
$proc->freeQueue();
\swoole_process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
