--TEST--
swoole_runtime: ftp fopen  wrapper
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    $file = 'work/test.txt';
    unlink(build_ftp_url($file));

    $fp = fopen(build_ftp_url($file), "w");
    Assert::notEmpty($fp);
    $bytes = random_bytes(8192);
    fwrite($fp, $bytes);
    fclose($fp);

    $fp = fopen(build_ftp_url($file), "r");
    Assert::notEmpty($fp);
    $read = fread($fp, 8192);
    Assert::eq($read, $bytes);
    fclose($fp);

    echo "DONE\n";
});
?>
--EXPECTF--
DONE
