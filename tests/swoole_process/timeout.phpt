--TEST--
swoole_process: pipe read timeout
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0
--FILE--
<?php
$proc = new \swoole_process(function(\swoole_process $process) {
    sleep(5);
});
$r = $proc->start();
assert($r > 0);
ini_set("swoole.display_errors", "off");
$proc->setTimeout(0.5);
$ret = $proc->read();
assert($ret === false);
swoole_process::kill($proc->pid, SIGKILL);
\swoole_process::wait(true);
?>
--EXPECT--
