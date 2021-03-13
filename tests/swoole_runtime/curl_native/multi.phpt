--TEST--
swoole_runtime/curl_native: multi
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $ch1 = curl_init();
    $ch2 = curl_init();

    // 设置URL和相应的选项
    curl_setopt($ch1, CURLOPT_URL, "http://www.baidu.com/");
    curl_setopt($ch1, CURLOPT_HEADER, 0);
    curl_setopt($ch1, CURLOPT_RETURNTRANSFER, 1);

    curl_setopt($ch2, CURLOPT_URL, "http://www.gov.cn/");
    curl_setopt($ch2, CURLOPT_HEADER, 0);
    curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);

    $mh = curl_multi_init();

    curl_multi_add_handle($mh, $ch1);
    curl_multi_add_handle($mh, $ch2);

    $active = null;
    // 执行批处理句柄
    do {
        $mrc = curl_multi_exec($mh, $active);
    } while ($mrc == CURLM_CALL_MULTI_PERFORM);

    while ($active && $mrc == CURLM_OK) {
        $n = curl_multi_select($mh);
        if ($n != -1) {
            do {
                $mrc = curl_multi_exec($mh, $active);
            } while ($mrc == CURLM_CALL_MULTI_PERFORM);
        }
    }

    Assert::contains(curl_multi_getcontent($ch1), 'baidu.com');
    Assert::contains(curl_multi_getcontent($ch2), '中央人民政府门户网站');

    curl_multi_remove_handle($mh, $ch1);
    curl_multi_remove_handle($mh, $ch2);

    curl_multi_close($mh);
});
echo "Done\n";
?>
--EXPECT--
Done
