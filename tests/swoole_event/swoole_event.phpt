--TEST--
swoole_event: swoole_event_exit

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--

<?php
swoole_timer_tick(1, function() {
    echo "tick\n";
    swoole_event_exit();
});
Swoole\Event::wait();
?>
--EXPECT--
tick


