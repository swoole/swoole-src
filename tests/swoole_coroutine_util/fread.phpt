--TEST--
swoole_coroutine_util: fread
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    $fp = fopen(TEST_IMAGE, 'r');
    if ($fp) {
        $data = fread($fp, 1024 * 1024);
        Assert::same(md5($data), md5_file(TEST_IMAGE));
    } else {
        echo "ERROR\n";
    }
});
?>
--EXPECT--
