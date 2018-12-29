--TEST--
swoole_async: swoole_async_read
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
swoole_event_wait();
?>
--EXPECT--
SUCCESS
