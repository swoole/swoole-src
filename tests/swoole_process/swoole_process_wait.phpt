--TEST--
swoole_process: wait
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

$proc = new \swoole_process(function() {});
$pid = $proc->start();
$info = \swoole_process::wait(true);
assert($pid === $info["pid"]);
assert($info["code"] === 0);
assert($info["signal"] === 0);

$proc = new \swoole_process(function() { exit(1); });
$pid = $proc->start();
$info = \swoole_process::wait(true);
assert($pid === $info["pid"]);
assert($info["code"] === 1);
assert($info["signal"] === 0);

$proc = new \swoole_process(function() { \swoole_process::kill(posix_getpid(), SIGTERM); });
$pid = $proc->start();
$info = \swoole_process::wait(true);
assert($pid === $info["pid"]);
assert($info["code"] === 0);
assert($info["signal"] === SIGTERM);

echo "SUCCESS";
?>
--EXPECT--
SUCCESS