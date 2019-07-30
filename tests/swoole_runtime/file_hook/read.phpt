--TEST--
swoole_runtime/file_hook: read file
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

function readfile_co($file)
{
    $fp = fopen($file, 'r+');
    $content = '';
    while (!feof($fp))
    {
        $data = fread($fp, 1024);
        $content .= $data;
    }
    return $content;
}

$files = array(
    [
        'file' => SOURCE_ROOT_PATH . '/README.md',
        'hash'  => '',
    ],
    [
        'file' => SOURCE_ROOT_PATH . '/package.xml',
        'hash'  => '',
    ],
    [
        'file' => TEST_IMAGE,
        'hash'  => '',
    ],
);

foreach ($files as &$f)
{
    $f['hash'] = md5_file($f['file']);
}

swoole\runtime::enableCoroutine();

foreach ($files as $k => $v)
{
    go(function () use ($v, $k) {
        $content = readfile_co($v['file']);
        Assert::same(md5($content), $v['hash']);
    });
}

swoole_event_wait();
?>
--EXPECT--
