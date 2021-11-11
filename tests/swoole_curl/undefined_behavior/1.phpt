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

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () use ($ch) {
    curl_close($ch);
});

?>
--EXPECT--
