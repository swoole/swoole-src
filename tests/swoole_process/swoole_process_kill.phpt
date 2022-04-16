--TEST--
swoole_process: kill
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function() {
    sleep(PHP_INT_MAX);
});
$pid = $proc->start();
Swoole\Process::kill($pid, SIGKILL);
$i = \Swoole\Process::wait(true);
Assert::same($i["signal"], SIGKILL);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
