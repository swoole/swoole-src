--TEST--
swoole_process: pipe read timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function(\swoole_process $process) {
    sleep(5);
});
$r = $proc->start();
Assert::assert($r > 0);
ini_set("swoole.display_errors", "off");
$proc->setTimeout(0.5);
$ret = $proc->read();
Assert::false($ret);
swoole_process::kill($proc->pid, SIGKILL);
\swoole_process::wait(true);
?>
--EXPECT--
