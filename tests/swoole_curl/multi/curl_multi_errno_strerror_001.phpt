--TEST--
swoole_curl/multi: curl_multi_errno and curl_multi_strerror basic test
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
if (!extension_loaded("curl")) {
        exit("skip curl extension not loaded");
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () {
        $mh = curl_multi_init();
        $errno = curl_multi_errno($mh);
        echo $errno . PHP_EOL;
        echo curl_multi_strerror($errno) . PHP_EOL;

        try {
            curl_multi_setopt($mh, -1, -1);
        } catch (ValueError $exception) {
            echo $exception->getMessage() . "\n";
        }

        $errno = curl_multi_errno($mh);
        echo $errno . PHP_EOL;
        echo curl_multi_strerror($errno) . PHP_EOL;
    });
});
$output = $pm->getChildOutput();

Assert::contains($output, "0\nNo error");
if (PHP_VERSION_ID < 80000) {
    Assert::contains($output, "Warning: curl_multi_setopt(): Invalid curl multi configuration option");
} else {
    Assert::contains($output, "0\nNo error");
    Assert::contains($output, "curl_multi_setopt(): Argument #2 (\$option) is not a valid cURL multi option");
}
Assert::contains($output, "6\nUnknown option");
?>
--EXPECT--
