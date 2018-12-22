--TEST--
swoole_async: swoole_async_read

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$content = file_get_contents(TEST_IMAGE);
$filename = __DIR__ . '/tmp_file.jpg';

swoole_async_writefile($filename, $content, function ($filename)
{
    assert(md5_file($filename) == md5_file(TEST_IMAGE));
    echo "SUCCESS\n";
    unlink($filename);
    swoole_event_exit();
});
?>
--EXPECT--
SUCCESS
