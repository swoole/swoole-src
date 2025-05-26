--TEST--
swoole_curl/multi: multiple binding
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

use SwooleTest\CurlManager;
$cm = new CurlManager();
$cm->run(function ($host) {
    $ch1 = curl_init();
    curl_setopt($ch1, CURLOPT_URL, "{$host}/get.php?test=get");

    $mh1 = curl_multi_init();
    Assert::eq(curl_multi_add_handle($mh1, $ch1), 0);

    $mh2 = curl_multi_init();
    Assert::eq(curl_multi_add_handle($mh2, $ch1), CURLM_ADDED_ALREADY);
});
?>
--EXPECT--
