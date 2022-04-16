--TEST--
swoole_process: wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function() {});
$pid = $proc->start();
$info = \Swoole\Process::wait(true);
Assert::same($pid, $info["pid"]);
Assert::same($info["code"], 0);
Assert::same($info["signal"], 0);

$proc = new Swoole\Process(function() { exit(1); });
$pid = $proc->start();
$info = \Swoole\Process::wait(true);
Assert::same($pid, $info["pid"]);
Assert::same($info["code"], 1);
Assert::same($info["signal"], 0);

$proc = new Swoole\Process(function() { \Swoole\Process::kill(posix_getpid(), SIGTERM); });
$pid = $proc->start();
$info = \Swoole\Process::wait(true);
Assert::same($pid, $info["pid"]);
Assert::same($info["code"], 0);
Assert::same($info["signal"], SIGTERM);

echo "SUCCESS";
?>
--EXPECT--
SUCCESS
