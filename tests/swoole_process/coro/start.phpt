--TEST--
swoole_process/coro: start with coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$proc = new Swoole\Process(function () {
    co::sleep(0.2);
    echo "SUCCESS\n";
}, false, 1, true);

$r = $proc->start();
Assert::assert($r > 0);
$proc->close();

\Swoole\Process::wait(true);

?>
--EXPECT--
SUCCESS
