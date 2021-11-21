--TEST--
swoole_process: exit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function(Swoole\Process $proc) {
    $proc->exit(9);
});
$pid = $proc->start();

$i = \Swoole\Process::wait(true);
Assert::same($i["code"], 9);

echo "SUCCESS";
?>
--EXPECT--
SUCCESS
