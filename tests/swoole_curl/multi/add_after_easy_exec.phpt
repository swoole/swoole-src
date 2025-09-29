--TEST--
swoole_curl/multi: add handle after easy exec
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
    curl_setopt($ch1, CURLOPT_RETURNTRANSFER, 1);
    $rs = curl_exec($ch1);
    Assert::eq($rs, "Hello World!\nHello World!");

    $mh1 = curl_multi_init();
    Assert::eq(curl_multi_add_handle($mh1, $ch1), 0);
});
?>
--EXPECT--
