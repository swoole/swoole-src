--TEST--
swoole_curl: multi 4
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
            swoole_test_curl_multi(['sleep' => 0.2]);
            echo "Done\n";
        });
    }
});
?>
--EXPECT--
Done
Done
Done
Done
