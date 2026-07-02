--TEST--
swoole_curl/multi: add handle initialized before native curl hook
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
if (!extension_loaded("curl")) exit("skip curl extension not loaded");
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

$ch = curl_init();

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () use ($ch) {
    $mh = curl_multi_init();
    Assert::eq(@curl_multi_add_handle($mh, $ch), CURLM_BAD_EASY_HANDLE);
    Assert::eq(curl_multi_errno($mh), CURLM_BAD_EASY_HANDLE);
    echo "Done\n";
    curl_multi_close($mh);
});
?>
--EXPECT--
Done
