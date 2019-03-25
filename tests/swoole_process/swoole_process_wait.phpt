--TEST--
swoole_process: wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function() {});
$pid = $proc->start();
$info = \swoole_process::wait(true);
Assert::eq($pid, $info["pid"]);
Assert::eq($info["code"], 0);
Assert::eq($info["signal"], 0);

$proc = new \swoole_process(function() { exit(1); });
$pid = $proc->start();
$info = \swoole_process::wait(true);
Assert::eq($pid, $info["pid"]);
Assert::eq($info["code"], 1);
Assert::eq($info["signal"], 0);

$proc = new \swoole_process(function() { \swoole_process::kill(posix_getpid(), SIGTERM); });
$pid = $proc->start();
$info = \swoole_process::wait(true);
Assert::eq($pid, $info["pid"]);
Assert::eq($info["code"], 0);
Assert::eq($info["signal"], SIGTERM);

echo "SUCCESS";
?>
--EXPECT--
SUCCESS