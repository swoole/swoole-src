--TEST--
swoole_process: signal
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
(new \swoole_process(function() {exit;}))->start();
swoole_process::signal(SIGCHLD, function() {
    swoole_process::signal(SIGCHLD, null);
    swoole_event_exit();
    echo "SUCCESS";
});
?>
--EXPECT--
SUCCESS