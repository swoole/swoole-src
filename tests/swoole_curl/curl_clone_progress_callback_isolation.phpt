--TEST--
swoole_curl: Cloning a handle with a reset progress callback isolates later callback changes
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
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
Swoole\Coroutine\run(function () {
    $source = curl_init('file://' . __FILE__);
    curl_setopt($source, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($source, CURLOPT_NOPROGRESS, false);
    curl_setopt($source, CURLOPT_PROGRESSFUNCTION, static fn() => 0);
    curl_setopt($source, CURLOPT_PROGRESSFUNCTION, null);

    $copy = clone $source;
    $sourceCallbackCalled = false;
    curl_setopt($source, CURLOPT_PROGRESSFUNCTION, static function () use (&$sourceCallbackCalled): int {
        $sourceCallbackCalled = true;
        return 0;
    });

    $expected = file_get_contents(__FILE__);
    echo "Clone\n";
    var_dump(curl_exec($copy) === $expected);
    var_dump($sourceCallbackCalled);
    echo "Source\n";
    var_dump(curl_exec($source) === $expected);
    var_dump($sourceCallbackCalled);
});
?>
--EXPECT--
Clone
bool(true)
bool(false)
Source
bool(true)
bool(true)
