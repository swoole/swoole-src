--TEST--
swoole_runtime: ftp fopen  wrapper
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_no_ftp();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    $file = 'swoole-ftp-' . getmypid() . '.txt';

    $n  = 8192;
    $fp = fopen(build_ftp_url($file), 'w');
    Assert::notEmpty($fp);
    $bytes = random_bytes($n);
    Assert::eq(fwrite($fp, $bytes), strlen($bytes));
    fclose($fp);

    $fp = fopen(build_ftp_url($file), 'r');
    Assert::notEmpty($fp);

    $rbytes = '';
    while (!feof($fp) and strlen($rbytes) < strlen($bytes)) {
        $read = fread($fp, $n);
        Assert::notEmpty($read);
        $rbytes .= $read;
    }

    Assert::eq(strlen($rbytes), strlen($bytes));
    Assert::eq($rbytes, $bytes);
    fclose($fp);

    Assert::true(unlink(build_ftp_url($file)));
    echo "DONE\n";
});
?>
--EXPECTF--
DONE
