--TEST--
swoole_runtime: switch native curl hook to php curl hook
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
if (!extension_loaded("curl")) exit("skip curl extension not loaded");
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
Runtime::setHookFlags(SWOOLE_HOOK_CURL);

run(function () {
    $ch = curl_init();
    echo get_class($ch), "\n";
    curl_close($ch);
});
?>
--EXPECT--
Swoole\Curl\Handler
