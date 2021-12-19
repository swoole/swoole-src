--TEST--
swoole_curl: select twice
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
    $n = 4;
    while ($n--) {
        go(function () {
            swoole_test_curl_multi(['select_twice' => true]);
            echo "Done\n";
        });
    }
});
?>
--EXPECTREGEX--
Fatal error: Uncaught Swoole\\Error: cURL is executing, cannot be operated in [\w\W]*php:\d+
Stack trace:
#0 [\w\W]*php\(\d+\): curl_multi_select\([a-zA-Z\(\)]+\)
#1 ({main}|\[internal function\]: {closure}\(\))
(#\d {main})?\s+thrown in [\w\W]*php on line \d+
