--TEST--
swoole_async: linux native aio read

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

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
