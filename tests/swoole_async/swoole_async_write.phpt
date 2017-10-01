--TEST--
swoole_async: swoole_async_write

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

$tmpFile = __DIR__.'/tmpFile';

$data = '';
$offset = 0;

for ($i = 0; $i < 10; $i++)
{
    $size = rand(1000, 8192);
    $chunk = RandStr::gen($size);
    swoole_async_write($tmpFile, $chunk, $offset);

    $data .= $chunk;
    $offset += $size;
}


for ($i = 0; $i < 5; $i++)
{
    $size = rand(1000, 8192);
    $chunk = RandStr::gen($size);
    swoole_async_write($tmpFile, $chunk, $offset, function () use ($i) {
        echo "SUCCESS\n";
        if ($i == 4) {
            swoole_event_exit();
        }
    });

    $data .= $chunk;
    $offset += $size;
}
swoole_event::wait();

assert(md5($data) == md5_file($tmpFile));
unlink($tmpFile);
?>

--EXPECT--
SUCCESS
SUCCESS
SUCCESS
SUCCESS
SUCCESS
