--TEST--
swoole_curl/basic: Test curl_exec() function with basic functionality
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

$ch = curl_init();

$test_fn = function () use ($ch) {
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, "http://www.gov.cn/");

    $curl_content = curl_exec($ch);
    Assert::contains($curl_content, '中国政府网');
    curl_close($ch);
};

$test_fn();

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () use ($test_fn) {
    $test_fn();
});

?>
--EXPECT--
