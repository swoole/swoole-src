--TEST--
swoole_process: start
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function() {
    echo "SUCCESS";
});
$r = $proc->start();
Assert::assert($r > 0);
$proc->close();

\Swoole\Process::wait(true);
?>
--EXPECT--
SUCCESS
