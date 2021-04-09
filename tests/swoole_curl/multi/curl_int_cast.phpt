--TEST--
swoole_curl/multi: Casting CurlHandle to int returns object ID
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $handle1 = curl_init();
    var_dump((int)$handle1);
    $handle2 = curl_init();
    var_dump((int)$handle2);

// NB: Unlike resource IDs, object IDs are reused.
    unset($handle2);
    $handle3 = curl_init();
    var_dump((int)$handle3);

// Also works for CurlMultiHandle.
    $handle4 = curl_multi_init();
    var_dump((int)$handle4);
});

?>
--EXPECTF--
int(%d)
int(%d)
int(%d)
int(%d)
