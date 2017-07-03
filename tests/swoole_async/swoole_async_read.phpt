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

swoole_async_read(__FILE__, function ($filename, $content) {
    $size = strlen($content);
    if ($size === 0) {
        echo "SUCCESS";
        return false;
    } else {
        assert(filesize(__FILE__) === $size);
        return true;
    }
}, 8192);
?>

--EXPECT--
SUCCESS


--CLEAN--