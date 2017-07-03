--TEST--
swoole_process: write
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
    $r = $process->write("SUCCESS");
    assert($r === 7);
});
$r = $proc->start();
assert($r > 0);


swoole_timer_after(10, function() use($proc) {
    echo $proc->read();
});

\swoole_process::wait(true);
?>
--EXPECT--
SUCCESS