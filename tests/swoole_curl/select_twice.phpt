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
--EXPECTF--
Fatal error: Uncaught Swoole\Error: cURL is executing, cannot be operated in %s:%d
Stack trace:
#0 %s(%d): curl_multi_select(%s)
#1 {main}
  thrown in %s on line %d
