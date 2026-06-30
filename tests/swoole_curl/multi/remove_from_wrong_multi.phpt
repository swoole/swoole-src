--TEST--
swoole_curl/multi: remove handle from wrong multi handle
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

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $ch = curl_init();
    $mh1 = curl_multi_init();
    $mh2 = curl_multi_init();

    Assert::eq(curl_multi_add_handle($mh1, $ch), CURLM_OK);
    curl_multi_remove_handle($mh2, $ch);

    var_dump(curl_multi_remove_handle($mh1, $ch) === CURLM_OK);
    curl_multi_close($mh2);
    curl_multi_close($mh1);
});
?>
--EXPECT--
bool(true)
