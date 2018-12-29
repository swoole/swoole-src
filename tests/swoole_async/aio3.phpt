--TEST--
swoole_async: linux native aio write
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const N = 10;

$data = '';
$count = 0;
$sets = 'ABCDEFGHIJK';
for ($i = 0; $i < N; $i++)
{
    $wData = str_repeat($sets[$i], 1023) . "\n";
    $data .= $wData;
    swoole_async_write(__DIR__ . '/tmp', $wData, $i * 1024, function ($filename, $length) use (&$data, &$count)
    {
        $count ++;
        if ($count == N) {
            swoole_event::defer(function() use ($data) {
                assert(md5_file(__DIR__. '/tmp') == md5($data));
                echo "SUCCESS\n";
                unlink(__DIR__. '/tmp');
            });
        }
    });
}

swoole_event_wait();

?>
--EXPECT--
SUCCESS
