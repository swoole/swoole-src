--TEST--
swoole_curl/undefined_behavior: 3
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    $ch = curl_init();
    run(function () use ($ch) {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_URL, "http://www.gov.cn/");

        $curl_content = curl_exec($ch);
        Assert::contains($curl_content, '中国政府网');
    });
    Runtime::enableCoroutine(0);
    curl_close($ch);
});
$output = $pm->getChildOutput();
if (PHP_VERSION_ID < 80000) {
    $pm->expectExitCode(0);
    Assert::contains($output, "curl_close(): supplied resource is not a valid cURL handle resource");
} else {
    $pm->expectExitCode(0);
}
?>
--EXPECT--
