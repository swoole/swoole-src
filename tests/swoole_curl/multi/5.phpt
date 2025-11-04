--TEST--
swoole_curl/multi: 5
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_API_PATH . '/curl_multi.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
run(function () {
    $ch1 = curl_init();
    curl_setopt($ch1, CURLOPT_URL, TEST_DOMAIN_1);
    curl_setopt($ch1, CURLOPT_RETURNTRANSFER, 1);

    $ch2 = curl_init();
    curl_setopt($ch2, CURLOPT_URL, TEST_DOMAIN_2);
    curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);

    $mh = curl_multi_init();
    curl_multi_add_handle($mh, $ch1);
    curl_multi_add_handle($mh, $ch2);

    do {
        $mrc = curl_multi_exec($mh, $active);
    } while ($mrc == CURLM_CALL_MULTI_PERFORM);

    while ($active && $mrc == CURLM_OK) {
        Assert::true(curl_multi_select($mh) != -1);
        do {
            $mrc = curl_multi_exec($mh, $active);
        } while ($mrc == CURLM_CALL_MULTI_PERFORM);
    }
    echo "DONE\n";
});
?>
--EXPECT--
DONE
