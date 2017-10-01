--TEST--
swoole_async: linux native aio readfile & writefile

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

swoole_async::set(array('aio_mode' => SWOOLE_AIO_LINUX));

swoole_async_readfile(TEST_IMAGE, function ($filename, $content)
{
    assert(md5_file($filename) == md5($content));
    $wFile = __DIR__ . '/tmp';
    $wData = str_repeat('A', 8192 * 128);
    swoole_async::writeFile($wFile, $wData, function ($file) use ($wData)
    {
        assert(md5_file($file) == md5($wData));
        echo "SUCCESS\n";
        swoole_event::defer(function() use ($file) {
            unlink($file);
        });
    });
    echo "SUCCESS\n";
});
?>
--EXPECT--
SUCCESS
SUCCESS
