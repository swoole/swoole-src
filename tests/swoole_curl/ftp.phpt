--TEST--
swoole_curl: ftp
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ftp();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $fileName = __DIR__ . '/upload/curl_testdata1.txt';
    $fp = fopen($fileName, 'r');
    $ftpUrl = build_ftp_url('1.txt');

    // upload
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $ftpUrl);
    curl_setopt($ch, CURLOPT_UPLOAD, true);
    curl_setopt($ch, CURLOPT_INFILE, $fp);
    curl_setopt($ch, CURLOPT_INFILESIZE, filesize($fileName));
    Assert::true(curl_exec($ch));
    Assert::eq(curl_errno($ch), 0);
    Assert::eq(curl_error($ch), '');
    curl_close($ch);
    fclose($fp);

    // download
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $ftpUrl);
    curl_setopt($ch, \CURLOPT_RETURNTRANSFER, 1);
    Assert::eq(curl_exec($ch), file_get_contents($fileName));
    Assert::eq(curl_errno($ch), 0);
    Assert::eq(curl_error($ch), '');
    curl_close($ch);
});
echo "Done\n";
?>
--EXPECT--
Done
