--TEST--
swoole_curl/setopt: CURLOPT_PREREQFUNCTION returning an invalid type releases the return value
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
skip('curl >= 7.80.0 is required', curl_version()['version_number'] < 0x075000);
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$cm = new SwooleTest\CurlManager();
$cm->run(function ($host) {
    $ch = curl_init("http://{$host}/get.php");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_PREREQFUNCTION, function () {
        return ['this should be an integer' => random_bytes(64)];
    });
    try {
        curl_exec($ch);
    } catch (TypeError $e) {
        echo $e->getMessage(), PHP_EOL;
    }
});
?>
--EXPECT--
The CURLOPT_PREREQFUNCTION callback must return either CURL_PREREQFUNC_OK or CURL_PREREQFUNC_ABORT
