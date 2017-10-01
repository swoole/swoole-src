--TEST--
swoole_async: swoole_async_read

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

swoole_async_readfile(TEST_IMAGE, function ($filename, $content) {
    assert(md5_file($filename) == md5($content));
    echo "SUCCESS\n";
});
?>
--EXPECT--
SUCCESS
