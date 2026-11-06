--TEST--
swoole_curl: curl_copy_handle() copies the read, header and write callbacks
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cm = new SwooleTest\CurlManager();
$cm->run(function ($host) {
    $reads = 0;
    $headers = 0;
    $body = '';

    $source = curl_init("http://{$host}/get.php?test=input");
    curl_setopt($source, CURLOPT_UPLOAD, true);
    curl_setopt($source, CURLOPT_INFILESIZE, 5);
    curl_setopt($source, CURLOPT_READFUNCTION, function ($ch, $fd, $length) use (&$reads) {
        return $reads++ === 0 ? 'Test.' : '';
    });
    curl_setopt($source, CURLOPT_HEADERFUNCTION, function ($ch, $header) use (&$headers) {
        $headers++;
        return strlen($header);
    });
    curl_setopt($source, CURLOPT_WRITEFUNCTION, function ($ch, $data) use (&$body) {
        $body .= $data;
        return strlen($data);
    });

    $ch = curl_copy_handle($source);
    unset($source);

    Assert::true(curl_exec($ch));
    Assert::greaterThan($reads, 0);
    Assert::greaterThan($headers, 0);
    Assert::same($body, 'Test.');
});

echo "DONE\n";
?>
--EXPECT--
DONE
