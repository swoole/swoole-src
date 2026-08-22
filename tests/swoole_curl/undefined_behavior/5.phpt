--TEST--
swoole_curl/undefined_behavior: 5
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function ($pm) {
    $mh = curl_multi_init();
    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($mh) {
        curl_multi_close($mh);
    });
});
$output = $pm->getChildOutput();
    $pm->expectExitCode(0);
?>
--EXPECT--
