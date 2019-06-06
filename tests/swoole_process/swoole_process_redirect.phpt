--TEST--
swoole_process: redirect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function(\swoole_process $proc) {
    echo "SUCCESS";
}, true);

$proc->start();
$r = $proc->read();
echo "READ: $r~";

\swoole_process::wait(true);
?>
--EXPECT--
READ: SUCCESS~
