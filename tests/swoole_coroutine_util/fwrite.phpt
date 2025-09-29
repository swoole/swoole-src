--TEST--
swoole_coroutine_util: fwrite
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    $file = __DIR__ . '/tmp';
    $fp = fopen($file, 'w+');
    $data = RandStr::gen(8192 * 8);
    if ($fp) {
        $ret = fwrite($fp, $data);
        if ($ret) {
            Assert::same(md5($data), md5_file($file));
            unlink($file);
            return;
        }
    }
    unlink($file);
    echo "ERROR\n";
});
?>
--EXPECT--
