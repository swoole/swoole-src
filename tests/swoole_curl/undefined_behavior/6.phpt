--TEST--
swoole_curl/undefined_behavior: 6
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_API_PATH.'/curl_multi.php';

use Swoole\Runtime;
use function Swoole\Coroutine\run;

$pm = ProcessManager::exec(function ($pm) {
    $mh = curl_multi_init();

    $test_fn = function () use ($mh) {
        swoole_test_curl_multi_ex($mh);
    };

    $test_fn();

    Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    run(function () use ($test_fn) {
        $test_fn();
    });
});
$output = $pm->getChildOutput();
$pm->expectExitCode(0);
?>
--EXPECT--
