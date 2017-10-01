--TEST--
swoole_process: ctor
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
$proc = new \swoole_process(function() {
    assert(false);
});
unset($proc);
echo "SUCCESS";


?>
--EXPECT--
SUCCESS