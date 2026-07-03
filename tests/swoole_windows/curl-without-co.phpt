--TEST--
swoole_windows: coroutine http server
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$ch = curl_init();
$url = 'https://' . TEST_DOMAIN_3 . '/';
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);

$body = curl_exec($ch);
if ($body === false) {
    echo "ERROR: " . curl_error($ch) . "\n";
}
Assert::assert(is_string($body));
Assert::notEmpty($body);
Assert::same(curl_error($ch), '');
Assert::same(curl_getinfo($ch, CURLINFO_HTTP_CODE) > 0, true);
curl_close($ch);
echo "DONE\n";
?>
--EXPECT--
DONE
