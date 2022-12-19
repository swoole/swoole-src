--TEST--
swoole_curl: create before hook
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

//  Create a curl resource before the coroutine hook
$ch = curl_init();
Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
run(function () use ($ch) {
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_URL, "http://www.gov.cn/");
    $curl_content = curl_exec($ch);
    Assert::contains($curl_content, '中国政府网');
});
curl_close($ch);
Runtime::enableCoroutine(0);
?>
--EXPECT--
