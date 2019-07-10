--TEST--
swoole_process: kill
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function() {
    sleep(PHP_INT_MAX);
});
$pid = $proc->start();
swoole_process::kill($pid, SIGKILL);
$i = \swoole_process::wait(true);
Assert::same($i["signal"], SIGKILL);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
