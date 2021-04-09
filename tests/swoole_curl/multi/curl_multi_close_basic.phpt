--TEST--
swoole_curl/multi: curl_multi_close
--CREDITS--
Stefan Koopmanschap <stefan@php.net>
#testfest Utrecht 2009
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('curl')) print 'skip';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    $ch = curl_multi_init();
    curl_multi_close($ch);
    curl_type_assert($ch, 'Swoole-Coroutine-cURL-Multi-Handle', Swoole\Coroutine\Curl\MultiHandle::class);
});
?>
--EXPECT--
