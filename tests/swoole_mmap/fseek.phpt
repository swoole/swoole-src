--TEST--
swoole_mmap: fseek SEEK_END
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$tmpfile = tempnam(sys_get_temp_dir(),"mmap_seek_end_test");
$var1 = "swoole like i";
$var2 = "i like swoole";
file_put_contents($tmpfile,$var1);
$handler = Swoole\Mmap::open($tmpfile);
fseek($handler,strlen($var1),SEEK_END);
fwrite($handler,$var2);
echo file_get_contents($tmpfile);
unlink($tmpfile);
?>
--EXPECT--
i like swoole
