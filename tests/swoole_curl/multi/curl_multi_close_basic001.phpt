--TEST--
swoole_curl/multi: curl_multi_close return false when supplied resource not valid cURL multi handle
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('curl')) print 'skip';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $cmh = curl_multi_init();
    curl_type_assert($cmh, 'Swoole-Coroutine-cURL-Multi-Handle', CurlMultiHandle::class);
    $multi_close_result = curl_multi_close($cmh);
    Assert::null($multi_close_result);
    curl_type_assert($cmh, 'Swoole-Coroutine-cURL-Multi-Handle', CurlMultiHandle::class);
    curl_multi_close($cmh);
});
?>
--EXPECT--
