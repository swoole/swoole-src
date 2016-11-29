<?php
$file = '/tmp/data';
$size = 8192;

if (!is_file($file)) {
    file_put_contents($file, str_repeat("\0", $size));
}

$fp = swoole\mmap::open($file, 8192);

fwrite($fp, "hello world\n");
fwrite($fp, "hello swoole\n");

fflush($fp);
fclose($fp);
