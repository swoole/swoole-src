--TEST--
swoole_process: exec
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function(\swoole_process $proc) {
    $proc->exec("/usr/bin/printf", ["HELLO"]);
}, true);
$proc->start();
echo $proc->read();
$proc->exec("/usr/bin/printf", [" WORLD"]);

\swoole_process::wait(true);
?>
--EXPECT--
HELLO WORLD
