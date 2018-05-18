--TEST--
swoole_coroutine: Co::readFile

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

go(function () {
    $content = Co::readFile(TEST_IMAGE);
    assert(md5_file(TEST_IMAGE) == md5($content));
});
?>
--EXPECT--
