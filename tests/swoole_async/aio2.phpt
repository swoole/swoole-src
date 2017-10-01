--TEST--
swoole_async: linux native aio read

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

$data = '';
swoole_async_read(TEST_IMAGE, function ($filename, $content) use (&$data)
{
    if ($content)
    {
        $data .= $content;
    }
    else
    {
        assert(md5($data) == md5_file(TEST_IMAGE));
    }
    return true;
});
?>
--EXPECT--
