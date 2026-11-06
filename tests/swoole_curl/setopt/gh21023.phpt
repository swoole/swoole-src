--TEST--
swoole_curl/setopt: GH-21023 (crash with CURLOPT_XFERINFOFUNCTION set with an invalid callback)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new SwooleTest\CurlManager();
$cm->run(function ($host) {
    $url = "http://{$host}/get.php";
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_NOPROGRESS, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_XFERINFOFUNCTION, null);
    curl_exec($ch);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_PROGRESSFUNCTION, null);
    curl_exec($ch);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_WILDCARDMATCH, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FNMATCH_FUNCTION, null);
    curl_exec($ch);
});
echo "OK", PHP_EOL;
?>
--EXPECT--
OK
