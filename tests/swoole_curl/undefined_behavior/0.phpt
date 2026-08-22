--TEST--
swoole_curl/undefined_behavior: 0
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
        $GLOBALS['ch'] = curl_init();
    });
    Runtime::enableCoroutine(0);
    curl_close($GLOBALS['ch']);
});
$output = $pm->getChildOutput();
    $pm->expectExitCode(0);
?>
--EXPECT--
