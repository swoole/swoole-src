--TEST--
swoole_curl/setopt: native CURLOPT_PREREQFUNCTION detection
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
if (!extension_loaded('curl')) {
    exit('skip curl extension not loaded');
}

// Only a native definition is accepted by ext/curl; Swoole's global fallback is an unknown option.
// Skipping on defined() alone would skip the broken baseline this test catches.
if (defined('CURLOPT_PREREQFUNCTION')) {
    $ch = curl_init();
    try {
        $supported = curl_setopt($ch, constant('CURLOPT_PREREQFUNCTION'), null);
    } catch (ValueError) {
        $supported = false;
    }
    curl_close($ch);

    if ($supported) {
        exit('skip native curl already supports CURLOPT_PREREQFUNCTION');
    }
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require_once TESTS_LIB_PATH . '/vendor/autoload.php';

// Swoole must not make native clients detect a curl capability that ext/curl does not provide.
Assert::false(
    defined('CURLOPT_PREREQFUNCTION'),
    'Swoole must not define the global CURLOPT_PREREQFUNCTION when native curl lacks it',
);
Assert::false(defined('CURL_PREREQFUNC_OK'));
Assert::false(defined('CURL_PREREQFUNC_ABORT'));
Assert::same(constant('Swoole\Curl\CURLOPT_PREREQFUNCTION'), 20312);
Assert::same(constant('Swoole\Curl\CURL_PREREQFUNC_OK'), 0);
Assert::same(constant('Swoole\Curl\CURL_PREREQFUNC_ABORT'), 1);

// Guzzle clears this option when releasing a handle whenever the global constant exists.
$cm = new SwooleTest\CurlManager();
$cm->run(function ($host) {
    $client   = new GuzzleHttp\Client();
    $response = $client->get("http://{$host}/get.php");

    Assert::same($response->getStatusCode(), 200);
    Assert::same((string) $response->getBody(), "Hello World!\nHello World!");
});

echo "DONE\n";
?>
--EXPECT--
DONE
