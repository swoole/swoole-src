--TEST--
swoole_process: write
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function(Swoole\Process $process) {
    $r = $process->write("SUCCESS");
    Assert::same($r, 7);
});
$r = $proc->start();
Assert::assert($r > 0);

Swoole\Timer::after(10, function() use($proc) {
    echo $proc->read();
});

\Swoole\Process::wait(true);
?>
--EXPECT--
SUCCESS
