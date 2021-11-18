--TEST--
swoole_process: redirect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function(Swoole\Process $proc) {
    echo "SUCCESS";
}, true);

$proc->start();
$r = $proc->read();
echo "READ: $r~";

\Swoole\Process::wait(true);
?>
--EXPECT--
READ: SUCCESS~
