--TEST--
swoole_curl/setopt: CURLOPT_PREREQFUNCTION
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
if (!extension_loaded('curl')) {
    exit('skip curl extension not loaded');
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

// The fallback constants are namespaced only when native curl omits the globals.
$option = defined('Swoole\Curl\CURLOPT_PREREQFUNCTION')
    ? constant('Swoole\Curl\CURLOPT_PREREQFUNCTION')
    : CURLOPT_PREREQFUNCTION;
$result = defined('Swoole\Curl\CURL_PREREQFUNC_OK')
    ? constant('Swoole\Curl\CURL_PREREQFUNC_OK')
    : CURL_PREREQFUNC_OK;

$cm = new SwooleTest\CurlManager();
$cm->disableNativeCurl();
$cm->run(function ($host) use ($option, $result) {
    $invocations = 0;
    $ch          = curl_init("http://{$host}/get.php");

    Assert::isInstanceOf($ch, Swoole\Curl\Handler::class);
    Assert::true(curl_setopt($ch, CURLOPT_RETURNTRANSFER, true));
    Assert::true(curl_setopt($ch, $option, function () use (&$invocations, $result): int {
        $invocations++;
        return $result;
    }));

    Assert::same(curl_exec($ch), "Hello World!\nHello World!");
    Assert::same($invocations, 1);
    curl_close($ch);
});

echo "DONE\n";
?>
--EXPECT--
DONE
