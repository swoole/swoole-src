--TEST--
swoole_runtime: ftp fopen  wrapper
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_in_ci('failure');
skip_if_no_ftp();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    $file = FTP_TEST_FILE;
    unlink(build_ftp_url($file));

    $n = 8192;
    $fp = fopen(build_ftp_url($file), "w");
    Assert::notEmpty($fp);
    $bytes = random_bytes($n);
    Assert::eq(fwrite($fp, $bytes), strlen($bytes));
    fsync($fp);
    fclose($fp);

    $fp = fopen(build_ftp_url($file), "r");
    Assert::notEmpty($fp);

    $rbytes = '';
    while (!feof($fp) and strlen($rbytes) < strlen($bytes)) {
       $read = fread($fp, $n);
       Assert::notEmpty($read);
       $rbytes .= $read;
    }

    Assert::eq(strlen($read), strlen($bytes));
    Assert::eq($read, $bytes);
    fclose($fp);

    echo "DONE\n";
});
?>
--EXPECTF--
DONE
