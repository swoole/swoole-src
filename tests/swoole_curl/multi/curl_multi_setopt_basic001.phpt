--TEST--
swoole_curl/multi: curl_multi_setopt basic test
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
if (!extension_loaded("curl")) {
        exit("skip curl extension not loaded");
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $mh = curl_multi_init();
    var_dump(curl_multi_setopt($mh, CURLMOPT_PIPELINING, 0));

    try {
        curl_multi_setopt($mh, -1, 0);
    } catch (ValueError $exception) {
        echo $exception->getMessage() . "\n";
    }
    curl_multi_close($mh);
});
?>
--EXPECTF--
bool(true)

Warning: curl_multi_setopt(): Invalid curl multi configuration option in %s on line %d
