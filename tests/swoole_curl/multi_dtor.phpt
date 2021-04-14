--TEST--
swoole_curl: multi dtor
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once TESTS_API_PATH.'/curl_multi.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $ch1 = curl_init();
    curl_setopt($ch1, CURLOPT_URL, "http://www.baidu.com/");
    curl_setopt($ch1, CURLOPT_HEADER, 0);
    curl_setopt($ch1, CURLOPT_RETURNTRANSFER, 1);

    $mh = curl_multi_init();
    curl_multi_add_handle($mh, $ch1);
    echo "Done\n";
});
?>
--EXPECT--
Done
