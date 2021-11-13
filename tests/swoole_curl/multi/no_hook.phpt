--TEST--
swoole_curl/multi: no hook
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_API_PATH.'/curl_multi.php';

use Swoole\Runtime;

Runtime::enableCoroutine(0);
swoole_test_curl_multi();
echo "Done\n";
?>
--EXPECT--
Done
