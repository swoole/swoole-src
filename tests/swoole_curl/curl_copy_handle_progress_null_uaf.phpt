--TEST--
swoole_curl: Cloning a curl handle whose CURLOPT_PROGRESSFUNCTION was reset to null must not reference the source handle
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
skip_if_extension_not_exist('curl');
skip('native curl hook is required', !defined('SWOOLE_HOOK_NATIVE_CURL'));
skip('file protocol not supported', !in_array('file', curl_version()['protocols'], true));
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
Swoole\Coroutine\run(function () {
    $srcfile = __DIR__ . '/curl_copy_handle_progress_null_uaf.txt';
    file_put_contents($srcfile, "Test.");

    $ch1 = curl_init();
    curl_setopt($ch1, CURLOPT_URL, "file://" . $srcfile);
    curl_setopt($ch1, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch1, CURLOPT_NOPROGRESS, false);
    curl_setopt($ch1, CURLOPT_PROGRESSFUNCTION, fn() => 0);
    curl_setopt($ch1, CURLOPT_PROGRESSFUNCTION, null);

    $ch2 = clone $ch1;
    unset($ch1);

    var_dump(curl_exec($ch2));
});
?>
--CLEAN--
<?php
@unlink(__DIR__ . '/curl_copy_handle_progress_null_uaf.txt');
?>
--EXPECT--
string(5) "Test."
