--TEST--
swoole_process: exit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function(\swoole_process $proc) {
    $proc->exit(9);
});
$pid = $proc->start();

$i = \swoole_process::wait(true);
Assert::same($i["code"], 9);

echo "SUCCESS";
?>
--EXPECT--
SUCCESS
