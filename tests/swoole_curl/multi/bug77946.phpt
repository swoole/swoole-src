--TEST--
swoole_curl/multi: Bug #77946 (Errored cURL resources returned by curl_multi_info_read() must be compatible with curl_errno() and curl_error())
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php

if (!extension_loaded('curl')) {
    exit('skip curl extension not loaded');
}

?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;
Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);

run(function () {
    $urls = array(
        'unknown://scheme.tld',
    );

    $mh = curl_multi_init();

    foreach ($urls as $i => $url) {
        $conn[$i] = curl_init($url);
        curl_multi_add_handle($mh, $conn[$i]);
    }

    do {
        $status = curl_multi_exec($mh, $active);
        $info = curl_multi_info_read($mh);
        if (false !== $info) {
            Assert::eq($info['result'], 1);
            Assert::eq(curl_errno($info['handle']), CURLE_UNSUPPORTED_PROTOCOL);
            Assert::contains(curl_error($info['handle']), 'Protocol "unknown" not supported');
        }
    } while ($status === CURLM_CALL_MULTI_PERFORM || $active);

    foreach ($urls as $i => $url) {
        curl_close($conn[$i]);
    }

    curl_multi_close($mh);
});
?>
--EXPECT--
