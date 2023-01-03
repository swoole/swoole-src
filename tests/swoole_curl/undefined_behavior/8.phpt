--TEST--
swoole_curl/undefined_behavior: 8
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_php_version_lower_than('8.0');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

//  Create a curl resource before the coroutine hook
$ch = curl_init();
Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () use ($ch) {
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, "http://www.gov.cn/");
    $curl_content = curl_exec($ch);
    Assert::false($curl_content);
});
curl_close($ch);
Runtime::enableCoroutine(0);
?>
--EXPECTF--
Warning: curl_exec(): The given handle is not initialized in coroutine in %s on line %d
