--TEST--
swoole_curl/undefined_behavior: 1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function ($pm) {
    $ch = curl_init();
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($ch) {
        curl_close($ch);
    });
});
$output = $pm->getChildOutput();
    $pm->expectExitCode(0);
?>
--EXPECT--
