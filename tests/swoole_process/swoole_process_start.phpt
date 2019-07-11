--TEST--
swoole_process: start
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function() {
    echo "SUCCESS";
});
$r = $proc->start();
Assert::assert($r > 0);
$proc->close();

\swoole_process::wait(true);
?>
--EXPECT--
SUCCESS
