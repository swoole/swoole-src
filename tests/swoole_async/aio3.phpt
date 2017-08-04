--TEST--
swoole_async: linux native aio write

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
const N = 10;
swoole_async::set(array('aio_mode' => SWOOLE_AIO_LINUX));

$data = '';
$count = 0;
$sets = 'ABCDEFGHIJK';
for ($i = 0; $i < N; $i++)
{
    $wData = str_repeat($sets[$i], 1023) . "\n";
    $data .= $wData;
    swoole_async_write(__DIR__ . '/tmp', $wData, $i * 1024, function ($filename, $length) use ($data, &$count)
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

?>
--EXPECT--
SUCCESS
