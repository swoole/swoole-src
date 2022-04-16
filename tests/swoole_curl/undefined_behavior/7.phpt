--TEST--
swoole_curl/undefined_behavior: 7
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function ($pm) {
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () {
        $GLOBALS['mh'] = curl_multi_init();
    });
    Runtime::enableCoroutine(0);
    curl_multi_close($GLOBALS['mh']);
});
$output = $pm->getChildOutput();
if (PHP_VERSION_ID < 80000) {
    $pm->expectExitCode(0);
    Assert::contains($output, "Warning: curl_multi_close(): supplied resource is not a valid cURL Multi Handle resource");
} else {
    $pm->expectExitCode(0);
}
?>
--EXPECT--
