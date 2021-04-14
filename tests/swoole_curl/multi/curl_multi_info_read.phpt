--TEST--
swoole_curl/multi: array curl_multi_info_read ( resource $mh [, int &$msgs_in_queue = NULL ] );
--CREDITS--
marcosptf - <marcosptf@yahoo.com.br> - @phpsp - sao paulo - br
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('curl')) { print("skip"); }
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $urls = array(
        "file://" . __DIR__ . "/curl_testdata1.txt",
        "file://" . __DIR__ . "/curl_testdata2.txt",
    );

    $mh = curl_multi_init();
    foreach ($urls as $i => $url) {
        $conn[$i] = curl_init($url);
        curl_setopt($conn[$i], CURLOPT_RETURNTRANSFER, 1);
        curl_multi_add_handle($mh, $conn[$i]);
    }

    do {
        $status = curl_multi_exec($mh, $active);
    } while ($status === CURLM_CALL_MULTI_PERFORM || $active);

    while ($info = curl_multi_info_read($mh)) {
        Assert::count($info, 3);
    }

    foreach ($urls as $i => $url) {
        curl_close($conn[$i]);
    }
});
?>
--EXPECT--
