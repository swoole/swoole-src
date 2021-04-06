--TEST--
swoole_curl: multi 2
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require_once TESTS_API_PATH.'/curl_multi.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () {
    swoole_test_curl_multi(['sleep' => 0.2]);
    echo "Done\n";
});
?>
--EXPECT--
Done
