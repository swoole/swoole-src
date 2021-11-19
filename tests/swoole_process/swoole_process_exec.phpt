--TEST--
swoole_process: exec
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function(Swoole\Process $proc) {
    $proc->exec("/usr/bin/printf", ["HELLO"]);
}, true);
$proc->start();
echo $proc->read();
$proc->exec("/usr/bin/printf", [" WORLD"]);

\Swoole\Process::wait(true);
?>
--EXPECT--
HELLO WORLD
