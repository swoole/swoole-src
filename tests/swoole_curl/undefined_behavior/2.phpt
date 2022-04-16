--TEST--
swoole_curl/undefined_behavior: 2
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;
use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function ($pm) {
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
});
$output = $pm->getChildOutput();
if (PHP_VERSION_ID < 80000) {
    $pm->expectExitCode(255);
    Assert::contains($output, "curl_setopt(): supplied resource is not a valid Swoole-Coroutine-cURL-Handle resource");
} else {
    $pm->expectExitCode(0);
}
?>
--EXPECT--
